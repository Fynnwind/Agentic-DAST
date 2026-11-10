"""The two triage passes: the deterministic arm and the LLM screening/synthesis arm.

Builds each endpoint\'s bundle and per-endpoint screening calls, runs the
whole-corpus synthesis pass, and holds the config and OpenRouter clients both
passes share. Depends only on :mod:`~dast_orchestrator.stages.triage.common`.
"""
from __future__ import annotations
import time
from collections import deque
from concurrent.futures import ThreadPoolExecutor, as_completed
from contextlib import ExitStack
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable
from dast_orchestrator.foundation import config
from dast_orchestrator.analysis import join
from dast_orchestrator.context import evidence
from dast_orchestrator.analysis import screening
from dast_orchestrator.adapters import retrieval as retrieval_mod
from dast_orchestrator.analysis import synthesize
from dast_orchestrator.foundation import prompts
from dast_orchestrator.foundation import ui
from dast_orchestrator.analysis.join import Bundle
from dast_orchestrator.analysis.screening import LlmError
from .common import *

def _triage_bundle(
    client: "screening.OpenRouterCorrelator",
    bundle: Bundle,
    pairs: list[tuple[str, Any]],
    cross_endpoint: dict[str, Any] | None = None,
    system_prompt: str | None = None,
    assembler: "evidence.Assembler | None" = None,
    retrieval: "retrieval_mod.Retrieval | None" = None,
    oracle: "dict[str, Any] | None" = None,
    max_alerts_per_call: int = screening.MAX_ALERTS_PER_CALL,
) -> tuple[list[tuple[list[str], dict[str, Any]]], list[str], int]:
    """Do one endpoint's calls and return what came back. **No shared state.**

    Runs in a worker thread, so it deliberately touches nothing but the client
    (whose accounting is locked): the ``findings`` list is mutated only by the
    caller, on the main thread. That is what keeps a concurrent run's *result*
    identical to a sequential one instead of merely usually identical.

    In pull mode the endpoint also gets **its own** retrieval session — one
    stdio subprocess per worker rather than one pipe shared between them — which
    is the same rule applied to the new state: the context server is read-only,
    so two sessions cannot disagree, and a shared pipe could interleave.

    :returns: ``(responses, log_lines, calls_made)`` where each response is
        paired with the finding ids it was asked about.
    """
    session = retrieval.session(bundle.identifier) if retrieval else None
    try:
        return _triage_calls(client, bundle, pairs, cross_endpoint,
                             system_prompt, assembler, retrieval, session,
                             oracle, max_alerts_per_call)
    finally:
        if session is not None:
            session.close()


def _triage_calls(
    client: "screening.OpenRouterCorrelator",
    bundle: Bundle,
    pairs: list[tuple[str, Any]],
    cross_endpoint: dict[str, Any] | None,
    system_prompt: str | None,
    assembler: "evidence.Assembler | None",
    retrieval: "retrieval_mod.Retrieval | None",
    session: Any,
    oracle: "dict[str, Any] | None" = None,
    max_alerts_per_call: int = screening.MAX_ALERTS_PER_CALL,
) -> tuple[list[tuple[list[str], dict[str, Any]]], list[str], int]:
    """One endpoint's chunked calls; :func:`_triage_bundle` owns the session."""
    pull = {
        "retrieval": session,
        "retrieval_tools": retrieval.tools if retrieval else None,
        "max_retrievals": retrieval.max_calls if retrieval else 0,
        # Identical on every call of the run, so it rides with the other
        # per-call extras rather than being threaded through each call site.
        "oracle": oracle,
    }
    responses: list[tuple[list[str], dict[str, Any]]] = []
    lines: list[str] = []
    # A queue, not a fixed list: a truncated chunk is replaced by its two halves
    # and retried, so an endpoint whose answers do not fit one call is still
    # answered rather than lost. Each entry is (chunk, output ceiling); a chunk
    # that cannot be split gets more room instead.
    queue = deque(
        (chunk, screening.MAX_TOKENS)
        for chunk in screening.chunk_alerts(pairs, max_alerts_per_call)
    )
    calls_made = 0
    while queue:
        chunk, ceiling = queue.popleft()
        calls_made += 1
        try:
            response = client.analyse(bundle, chunk, max_tokens=ceiling,
                                      cross_endpoint=cross_endpoint,
                                      system_prompt=system_prompt,
                                      assembler=assembler, **pull)
        except LlmError as exc:
            if (
                exc.kind == "truncated"
                and len(chunk) == 1
                and ceiling < screening.RETRY_MAX_TOKENS
            ):
                # A single alert has no smaller form; the only lever left is a
                # bigger budget.
                queue.appendleft((chunk, screening.RETRY_MAX_TOKENS))
                lines.append(
                    f"  [llm] {bundle.identifier}: 1 alert truncated at "
                    f"{ceiling}, retrying at {screening.RETRY_MAX_TOKENS}"
                )
                continue
            if exc.kind == "truncated" and len(chunk) > 1:
                middle = len(chunk) // 2
                queue.appendleft((chunk[middle:], ceiling))
                queue.appendleft((chunk[:middle], ceiling))
                client.usage.note_split()
                lines.append(
                    f"  [llm] {bundle.identifier}: response truncated, splitting "
                    f"{len(chunk)} alerts into {middle}+{len(chunk) - middle}"
                )
                continue
            # Same rule as seeding: a partial pass is reported, not fatal.
            client.usage.record_failure(exc.kind, f"{bundle.identifier}: {exc}")
            lines.append(
                f"  [llm] {bundle.identifier} [{len(chunk)} alerts]: FAILED ({exc})"
            )
            continue
        asked = [fid for fid, _ in chunk]
        responses.append((asked, response))

        # A short-but-valid answer is not an error, so nothing above catches it:
        # the model returns fewer verdicts than it was asked for and the missing
        # findings silently become asked-but-unanswered — a large fraction of a
        # cheap model's run. The schema now pins the count
        # (screening.verdicts_schema); this re-asks for whatever a
        # provider returned short anyway, exactly once, for exactly the ids that
        # are missing.
        missing = screening.missing_verdict_ids(response, asked)
        if missing and len(missing) < len(asked):
            retry_chunk = [pair for pair in chunk if pair[0] in set(missing)]
            calls_made += 1
            client.usage.note_retry()
            lines.append(
                f"  [llm] {bundle.identifier}: {len(missing)} of {len(asked)} "
                f"verdicts missing, re-asking for those"
            )
            try:
                second = client.analyse(bundle, retry_chunk, max_tokens=ceiling,
                                        cross_endpoint=cross_endpoint,
                                        system_prompt=system_prompt,
                                        assembler=assembler, **pull)
            except LlmError as exc:
                client.usage.record_failure(f"partial_retry_{exc.kind}",
                                            f"{bundle.identifier}: {exc}")
            else:
                responses.append(([fid for fid, _ in retry_chunk], second))
                still = screening.missing_verdict_ids(second, missing)
                if still:
                    client.usage.record_failure("partial_answer")
        elif missing:
            # Nothing came back at all for this chunk; re-asking the same
            # question the same way is not a plan.
            client.usage.record_failure("partial_answer")
    return responses, lines, calls_made


def triage_config(**values: Any) -> dict[str, Any]:
    """The triage settings that make two runs of one scan different experiments.

    The counterpart of :func:`dast_orchestrator.stages.scan.scan_config`, and the reason
    both exist: a triage does *not* mint a run directory — it re-reads a stored
    scan — so its configuration cannot ride in the run id. It rides in the
    metrics record and in the artifact suffix instead, which is what lets a
    model comparison or a variance repeat sit next to its baseline inside one
    run folder rather than paying for another active scan.

    Both prompt versions are in here on purpose: a prompt edit changes what the
    arm is, and two artifacts compared across a silent prompt change is the
    failure the version constants exist to prevent.
    """
    return values


def pass1_candidates(
    bundles: list[Bundle],
    max_endpoints: int = 0,
    prune_noninteractive_php: bool = False,
) -> tuple[list[Bundle], int]:
    """The endpoints pass 1 sends to the model, and how many php_pure were pruned.

    The one selection both :func:`run_llm_arm` and the code-context gate use, so
    the gate judges exactly the set the live arm would send.
    """
    candidates, pruned_php = join.select_llm_candidates(
        bundles, prune_noninteractive_php)
    if max_endpoints:
        candidates = candidates[:max_endpoints]
    return candidates, pruned_php


#: ZAP's risk as a rank, highest first; anything else sorts with Informational.
_RISK_RANK = {"High": 3, "Medium": 2, "Low": 1}


@dataclass
class Pass1Plan:
    """What pass 1 sends, fixed before the first call (:func:`plan_pass1`)."""

    #: ``(bundle, pairs)`` to call the model on, systemic duplicates folded out.
    work: list[tuple[Bundle, list[tuple[str, Any]]]]
    #: Folded instance -> representative, for representatives that are sent.
    fanout: dict[str, str]
    #: Every finding counted as asked: the sent ones and those folded into them.
    asked_ids: list[str]
    #: Candidates the limit left unsent, folded instances included.
    deferred_ids: list[str]
    #: Findings beyond the old gate, after the fold, and how many of them are sent.
    unmatched: int
    unmatched_sent: int
    #: ``deferred_ids`` counted by ZAP risk, highest first: what the limit cost.
    deferred_by_risk: dict[str, int]

    def deferred_note(self) -> str:
        """``"426 deferred (Informational 426)"``, or ``"0 deferred"``."""
        split = ", ".join(f"{risk} {n}" for risk, n in self.deferred_by_risk.items())
        return f"{len(self.deferred_ids)} deferred" + (f" ({split})" if split else "")


def plan_pass1(
    candidates: list[Bundle],
    findings: list[dict[str, Any]],
    max_unmatched_findings: int = config.NO_LIMIT,
    has_source: "Callable[[Bundle], bool] | None" = None,
) -> Pass1Plan:
    """The findings pass 1 asks, decided before any call so a repeat asks the same.

    Every finding of an endpoint with static context (the population before
    2026-11-02) is asked. The rest are ranked by ZAP risk, then source before
    none, then endpoint and finding id, and the first ``max_unmatched_findings``
    are asked (:data:`config.NO_LIMIT` asks all, ``0`` none). Counted after the
    systemic fold, whose representatives prefer static context, so no finding of
    the old population can fall behind the limit. → DECISIONS.md.

    :param has_source: whether an endpoint's handler source is in hand (the
        assembler, prepared over ``candidates``); ``None`` treats none as having it.
    """
    work = [(bundle, _findings_of(bundle, findings)) for bundle in candidates]
    work = [(bundle, pairs) for bundle, pairs in work if pairs]
    collapsed, fanout = collapse_systemic(work)
    source = has_source or (lambda _bundle: False)
    ranked = sorted(
        ((bundle, fid, group) for bundle, pairs in collapsed
         if not bundle.has_static_context for fid, group in pairs),
        key=lambda item: (-_RISK_RANK.get(item[2].risk, 0), not source(item[0]),
                          item[0].identifier, item[1]),
    )
    chosen = ranked if max_unmatched_findings < 0 else ranked[:max_unmatched_findings]
    chosen_ids = {fid for _bundle, fid, _group in chosen}
    sent: list[tuple[Bundle, list[tuple[str, Any]]]] = []
    for bundle, pairs in collapsed:
        kept = (pairs if bundle.has_static_context
                else [(fid, group) for fid, group in pairs if fid in chosen_ids])
        if kept:
            sent.append((bundle, kept))
    sent_ids = {fid for _bundle, pairs in sent for fid, _group in pairs}
    sent_fanout = {dup: rep for dup, rep in fanout.items() if rep in sent_ids}
    risk_of = {fid: group.risk for _bundle, pairs in work for fid, group in pairs}
    every = list(risk_of)
    asked = {fid for fid in every if fid in sent_ids or fid in sent_fanout}
    deferred = [fid for fid in every if fid not in asked]
    by_risk: dict[str, int] = {}
    for fid in sorted(deferred, key=lambda fid: -_RISK_RANK.get(risk_of[fid], 0)):
        by_risk[risk_of[fid]] = by_risk.get(risk_of[fid], 0) + 1
    return Pass1Plan(
        work=sent, fanout=sent_fanout,
        asked_ids=[fid for fid in every if fid in asked],
        deferred_ids=deferred,
        unmatched=len(ranked), unmatched_sent=len(chosen),
        deferred_by_risk=by_risk,
    )


class CodeContextUngrounded(RuntimeError):
    """Code context is on, yet no endpoint pass 1 would send has its own handler."""


def require_located_handlers(
    assembler: "evidence.Assembler | None", candidates: list[Bundle],
) -> None:
    """Refuse a run whose code context locates the handler of none of its endpoints.

    Prepares the assembler over ``candidates`` (cached, so the live arm reuses
    it) and checks :meth:`evidence.Assembler.grounding`. Passes when code context
    is off or not honoured, when there are no candidates, or when at least one
    candidate's handler is located; a partial count is recorded, never gated.

    :raises CodeContextUngrounded: code context is on, there is at least one
        candidate, and none has its handler located.
    """
    if assembler is None or not assembler.code_enabled or not candidates:
        return
    assembler.prepare(candidates)
    grounding = assembler.grounding(candidates)
    if grounding["handler_located"]:
        return
    tiers = ", ".join(f"{tier} {count}"
                      for tier, count in grounding["by_resolution"].items())
    raise CodeContextUngrounded(
        f"code context {assembler.code_level!r} is on, but none of the "
        f"{grounding['endpoints']} endpoint(s) pass 1 would send has its own "
        f"handler located (resolved by: {tiers}).\n"
        "       `code_paths` source is the endpoint's whole file, not a handler "
        "located for it,\n"
        "       so the run would claim a source grounding it does not have. To "
        "run without code context,\n"
        "       say so: --code-context none (TRIAGE_CODE_CONTEXT=none)."
    )


def run_llm_arm(
    bundles: list[Bundle],
    findings: list[dict[str, Any]],
    model: str,
    max_endpoints: int,
    api_key: str | None = None,
    concurrency: int = DEFAULT_CONCURRENCY,
    pass1_context: str = screening.DEFAULT_PASS1_CONTEXT,
    prompt: "prompts.Prompt | None" = None,
    stage_max_cost_usd: float = screening.UNLIMITED,
    run_max_cost_usd: float = screening.UNLIMITED,
    prior_cost_usd: float = 0.0,
    assembler: "evidence.Assembler | None" = None,
    retrieval_mode: str = retrieval_mod.DEFAULT_RETRIEVAL,
    max_retrievals: int = retrieval_mod.DEFAULT_MAX_CALLS,
    messages_path: "Path | None" = None,
    source_dir: "Path | None" = None,
    oracle: "dict[str, Any] | None" = None,
    provider: str = "",
    prune_noninteractive_php: bool = False,
    max_alerts_per_call: int = screening.MAX_ALERTS_PER_CALL,
    max_unmatched_findings: int = config.NO_LIMIT,
    max_minutes: float = config.NO_LIMIT,
) -> dict[str, Any]:
    """Pass 1: call the model once per candidate bundle, merging verdicts in.

    The calls run concurrently (:data:`DEFAULT_CONCURRENCY`), the merges do not.
    Three things make that safe rather than merely fast:

    * **Workers never touch shared state.** :func:`_triage_bundle` returns raw
      responses; ``findings`` is mutated only here, on one thread.
    * **The result does not depend on completion order.** A finding belongs to
      exactly one bundle, so two endpoints' merges are disjoint — merging as
      answers land gives the same artifact as merging in candidate order. The
      one order-sensitive output, the dropped-id list, is sorted.
    * **"Asked" is recorded up front**, for every candidate, before any call is
      dispatched — so an endpoint whose worker fails still leaves its findings
      marked asked-but-unanswered rather than looking never-asked.
    """
    candidates, pruned_php = pass1_candidates(
        bundles, max_endpoints, prune_noninteractive_php)
    if assembler is not None:
        # Built once, before the pool starts, and read-only for the whole pass;
        # prepared over every candidate because the plan ranks by its source.
        assembler.prepare(candidates)
    # Which findings are sent, fixed before any call: the old gate's in full, the
    # rest by risk up to the limit, systemic duplicates folded to representatives
    # whose verdict is fanned back after the pool rather than re-asked.
    plan = plan_pass1(candidates, findings, max_unmatched_findings,
                      assembler.has_source if assembler is not None else None)
    work, systemic_fanout = plan.work, plan.fanout

    unknown_ids: list[str] = []
    workers = max(1, min(int(concurrency or 1), len(work) or 1))
    # Built once, before the pool starts, and never written to again — see
    # screening.build_cross_endpoint_context for why it cannot be the
    # sibling *verdicts* without making the result depend on completion order.
    cross_context = screening.build_cross_endpoint_context(bundles, pass1_context)
    # Built before the pool, like everything else shared: the tool declaration
    # is read from the live server once, and a server that cannot answer fails
    # the run here rather than endpoint by endpoint after the money is spent.
    retrieval = None
    if retrieval_mode == retrieval_mod.PULL_MODE:
        retrieval = retrieval_mod.Retrieval.open(
            messages_path=messages_path,
            source_dir=source_dir,
            index_path=retrieval_mod.index_path_for(source_dir),
            max_calls=max_retrievals,
        )
    prompt = prompt or prompts.load("screening")
    ui.item("model", model)
    ui.item("prompt", f"{prompt.path.name} ({len(prompt.text)} chars)")
    ui.item("candidate endpoints",
            f"{len(work)}/{len(bundles)} forwarded to model")
    scope = ("no limit" if max_unmatched_findings < 0
             else f"limit {max_unmatched_findings}")
    ui.item("beyond the old gate",
            f"{plan.unmatched_sent} of {plan.unmatched} finding(s) sent ({scope}), "
            f"{plan.deferred_note()}")
    if pruned_php:
        ui.item("php prune",
                f"{pruned_php} php_pure cli/install endpoint(s) dropped from the "
                "LLM arm (--prune-noninteractive-php); deterministic record intact")
    if systemic_fanout:
        ui.item("systemic collapse",
                f"{len(systemic_fanout)} site-wide finding(s) folded to "
                "representatives (ZAP SYSTEMIC tag); verdict fanned back, "
                "not re-asked")
    ui.item("concurrency", f"{workers} call(s)")
    # Each context knob carries its setting AND what that setting actually
    # produced over the candidate endpoints, so there is no separate "evidence
    # pack" line to reconcile: `code context` names the level, the hop depth, how
    # many endpoints Noir gave callees for and how many of those ctags resolved
    # to source; `http context` names the excerpt policy and the exchanges on
    # disk it draws from.
    ui.item("peer context", pass1_context)
    if assembler is not None:
        provenance = assembler.as_dict()
        n = len(candidates)
        noir = sum(1 for c in candidates if c.has_static_context)
        if assembler.code_enabled:
            hops = assembler.max_hops
            ctag = provenance.get("endpoints_with_source", 0)
            located = provenance.get("endpoints_handler_located", 0)
            ui.item("code context",
                    f"{assembler.code_level} - {hops} hop{'s' if hops != 1 else ''}"
                    f" - {noir}/{n} noir resolved - {ctag}/{n} ctag resolved"
                    f" - {located}/{n} handler located")
        else:
            ui.item("code context",
                    f"{assembler.code_level} - {noir}/{n} noir resolved")
        ui.item("http context",
                f"{provenance['excerpt_policy']['name']} - "
                f"{provenance['http_exchanges_available']} HTTP exchanges")
    ui.item("retrieval", retrieval_mode)
    limit = screening.headroom(stage_max_cost_usd, run_max_cost_usd, prior_cost_usd)
    if limit >= 0:
        ui.item("cost ceiling",
                f"${limit:.4f}"
                + (f" (${prior_cost_usd:.4f} already spent by this run)"
                   if prior_cost_usd else ""))
    if max_minutes >= 0:
        ui.item("time limit", f"{max_minutes:g} min (a safety net, not a scope)")

    # Recorded before any call: a finding that is asked about and never answered
    # must stay distinguishable from one never sent at all, and both from one the
    # limit deferred. A folded systemic duplicate of a sent finding counts as asked.
    join.mark_asked(findings, plan.asked_ids)
    join.mark_deferred(findings, plan.deferred_ids)

    with screening.OpenRouterCorrelator(
        api_key=api_key, model=model,
        stage_max_cost_usd=stage_max_cost_usd, run_max_cost_usd=run_max_cost_usd,
        prior_cost_usd=prior_cost_usd, max_minutes=max_minutes,
        provider=provider,
    ) as client:
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = {
                pool.submit(_triage_bundle, client, bundle, pairs,
                            cross_context.get(bundle.identifier),
                            prompt.text, assembler, retrieval,
                            oracle, max_alerts_per_call): (bundle, pairs)
                for bundle, pairs in work
            }
            done = asked = answered = 0
            partial: list[str] = []
            # One bar over all the endpoints, on top of the per-endpoint rows —
            # how far through pass 1 we are and roughly how long is left, like
            # the ZAP stages. Driven from this thread only (results are consumed
            # here as they complete), so it is safe with the worker pool.
            ui.blank()  # separate the bar from the pass-1 header above it
            progress = ui.Progress("triage", step=0)
            started = time.monotonic()
            for future in as_completed(futures):
                bundle, pairs = futures[future]
                done += 1
                try:
                    responses, lines, calls_made = future.result()
                except Exception as exc:  # a worker must never take the run down
                    client.usage.record_failure(
                        "worker_error",
                        f"{bundle.identifier}: {type(exc).__name__}: {exc}")
                    # Through the bar, not straight to the terminal: a stray line
                    # would desync the fixed header's line count. It still reads
                    # as a warning (the `!`) and it advances the count.
                    progress.line(f"! {bundle.identifier}: FAILED ({exc})",
                                  done * 100 // len(work), time.monotonic() - started)
                    continue
                # Only what a reader must see: a failure, a split, a retry. The
                # per-endpoint roll-call was 59 lines saying "fine". Routed through
                # the bar for the same reason as the failure line above.
                for line in lines:
                    progress.line("! " + line.strip().removeprefix("[llm] "),
                                  done * 100 // len(work), time.monotonic() - started)
                applied = 0
                had_source = assembler is not None and assembler.has_source(bundle)
                for asked_ids, response in responses:
                    merged, unknown = screening.merge_verdicts(
                        findings, response, asked_ids, had_source=had_source
                    )
                    applied += merged
                    unknown_ids.extend(unknown)
                answered += applied
                asked += len(pairs)
                if applied < len(pairs):
                    partial.append(f"{bundle.identifier} ({applied}/{len(pairs)})")
                # One line per endpoint, naming the route: when an endpoint
                # answers only in part, *which* endpoint is the whole question,
                # and a condensed counter cannot say.
                note = f" in {calls_made} calls" if calls_made > 1 else ""
                short = "" if applied == len(pairs) else "  ← partial"
                progress.line(
                    f"{bundle.identifier:<44} {applied}/{len(pairs)} verdicts"
                    f"{note}{short}",
                    done * 100 // len(work), time.monotonic() - started)
            progress.close()

        if partial:
            ui.found(f"{len(partial)} of {len(work)} endpoints answered only in "
                     f"part — {answered} of {asked} verdicts returned")
        # Fan each site-wide verdict to the instances folded into its
        # representative. Identical (rule, evidence) means the model's answer is
        # the same, so this copies rather than re-asks — and records the
        # provenance (`fanned_from`) so the artifact never claims a folded
        # instance was independently judged. A representative whose own call
        # failed has no verdict to fan; its instances stay asked-but-unanswered.
        fanned = 0
        if systemic_fanout:
            fanned = fan_systemic_verdicts(findings, systemic_fanout)
            ui.found(f"{fanned} of {len(systemic_fanout)} folded systemic "
                     "verdict(s) fanned from their representatives")
        metadata = screening.run_metadata(
            model, client.usage, len(candidates), concurrency=workers,
            pass1_context=pass1_context, prompt=prompt,
            provider=client.provider_preference,
        )
        metadata["systemic_collapse"] = {
            "folded": len(systemic_fanout),
            "fanned": fanned,
        }
        metadata["scope"] = {
            "max_unmatched_findings": max_unmatched_findings,
            "unmatched": plan.unmatched,
            "unmatched_sent": plan.unmatched_sent,
            "deferred": len(plan.deferred_ids),
            "deferred_by_risk": plan.deferred_by_risk,
            "max_minutes": max_minutes,
        }
        # How many the gated non-interactive-PHP prune removed from THIS arm. In
        # the metadata so the artifact and the run digest can state which corpus
        # the model actually saw — a run with the prune on saw a different one.
        metadata["pruned_noninteractive_php"] = pruned_php

    # Sorted, not append-ordered: with a pool the arrival order varies, and this
    # list is the only place it could have leaked into the artifact.
    metadata["dropped_unknown_finding_ids"] = sorted(unknown_ids)
    if retrieval is not None:
        metadata["retrieval"] = retrieval.as_dict()
        pulled = retrieval.log
        ui.found(
            f"{pulled.calls} retrieval(s), {pulled.bytes_returned} bytes pulled "
            f"across {len(work)} endpoint(s)"
            + (f" — {pulled.failures} failed" if pulled.failures else "")
        )
    else:
        metadata["retrieval"] = {"mode": retrieval_mod.PUSH_MODE}
    return metadata


def run_synthesis_arm(
    bundles: list[Bundle],
    findings: list[dict[str, Any]],
    scan_summary: dict[str, Any],
    model: str,
    api_key: str | None = None,
    prompt: "prompts.Prompt | None" = None,
    repeats: int = synthesize.DEFAULT_REPEATS,
    concurrency: int = DEFAULT_CONCURRENCY,
    models: "list[str] | None" = None,
    oracle: "dict[str, Any] | None" = None,
    provider: str = "",
    providers: "list[str] | None" = None,
    timeout: "float | None" = None,
    max_prompt_tokens: int = 0,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Pass 2: N complete calls over the whole triaged scan, unioned.

    Each call is deliberately a *whole-corpus* call rather than a chunked sweep.
    Chunking is what makes pass 1 reliable, and it is exactly what would defeat
    this pass: a correlation spanning two endpoints is invisible if the two
    endpoints land in different calls. The corpus is built shallow (names, no
    source snippets) so the whole scan fits in one request.

    ``repeats`` makes several such calls and unions their claims
    (:func:`synthesize.merge_repeats`). That is sampling, not chunking — every
    repeat still sees the entire scan. It exists because the pass is undersampled
    rather than wrong: more repeats surface a reproducible cross-endpoint claim
    more reliably, at a few tenths of a cent a call against a 45-minute scan.

    ``models`` turns the repeats into an **ensemble**: each named model draws
    ``repeats`` samples of the same corpus, and the union additionally reports
    how many *models* reached each claim. That is a stronger reliability signal
    than recurrence within one model, whose samples share their failure modes —
    and it is a balanced design on purpose, ``repeats`` per model rather than
    ``repeats`` shared out, so per-model recurrence and cross-model agreement
    are both computable from one run. Empty (the default) is the single-model
    behaviour, unchanged down to the artifact's field names.

    :param model: the model the corpus-discovery call uses, and the whole
        ensemble when ``models`` is empty.
    :param models: the ensemble. ``model`` is used for the first sample whether
        or not it appears here, so the corpus fallback is decided once.
    :param providers: per-member OpenRouter providers, matched to ``models`` by
        position; a member absent from it falls back to ``provider``. Empty means
        every member uses ``provider``, the pre-ensemble behaviour. The caller
        validates the count and skips this pass on a mismatch.
    :param oracle: the target's documented vulnerabilities, in oracle-guided
        (``--ceiling``) runs only. This is the pass the knowledge should help
        most — it is the one that can trace a described weakness across a route
        family — so a per-stage ceiling breakdown is worth reading here first.
    """
    prompt = prompt or prompts.load("synthesis")
    # A per-call wall-clock deadline. This pass is the one that stalls — a
    # preference-routed provider can accept the ~135k-token whole-corpus request
    # and then never answer (one Cacti ceiling ran >182 min before a read
    # timeout). On expiry `complete` raises a non-transient ``timeout`` LlmError,
    # which the degrade path below turns into "no synthesis this run" rather than
    # a crash. ``None`` / <=0 keeps the pre-deadline unbounded behaviour.
    deadline = timeout if (timeout and timeout > 0) else None
    known_ids = [f["finding_id"] for f in findings]
    correlated: list[dict[str, Any]] = []
    dropped = 0
    failed: str | None = None
    # The discovery model leads: it is the one that finds out whether the corpus
    # fits, and every later sample reuses whatever corpus it settled on.
    ensemble = [model] + [m for m in (models or []) if m and m != model]
    # A member's provider comes from --synthesis-providers (matched to
    # --synthesis-models by position); absent that, it falls back to the single
    # ``provider`` — so an ensemble with no per-member providers behaves exactly
    # as before. The leader (``model``) always uses ``provider``. The length is
    # validated by the caller, which skips this pass on a mismatch.
    member_provider = dict(zip(models or [], providers or []))

    def describe(corpus: dict[str, Any]) -> int:
        chars = sum(len(m["content"])
                    for m in synthesize.build_messages(corpus, prompt.text))
        ui.item("model", model)
        ui.item("prompt", prompt.path.name)
        ui.item("corpus", f"{len(corpus['endpoints'])} endpoints, "
                          f"{corpus['scan_shape']['findings_shown']} findings")
        ui.item("shared handlers", len(corpus["shared_handlers"]))
        ui.item("prompt size", f"~{chars // 4} tokens, one call")
        return chars // 4

    # An ExitStack rather than one `with`: an ensemble opens a client per model
    # and every one of them has to be closed, whichever sample failed.
    with ExitStack() as stack:
        client = stack.enter_context(llm_synthesize_client(api_key, model, provider))
        # Pass 2 cannot chunk without defeating its own purpose, so a truncation
        # costs the whole pass. The one safe lever is a narrower corpus: fewer
        # endpoints, busiest first, same shape. A partial synthesis beats none.
        for attempt, endpoint_cap in enumerate(
            (synthesize.MAX_ENDPOINTS, synthesize.FALLBACK_MAX_ENDPOINTS)
        ):
            corpus = synthesize.build_corpus(
                bundles, findings, scan_summary, max_endpoints=endpoint_cap,
                oracle=oracle,
            )
            est_tokens = describe(corpus)
            # Pre-emptive skip: with an operator-set prompt-token cap (off by
            # default; 0 = unbounded) the whole-corpus call is NOT ATTEMPTED once
            # the prompt is over it — a distinct metric state from the two
            # failures a call can hit: `timeout` (a call made, then abandoned at
            # the deadline) and `context_overflow` (a provider's 400). This one is
            # "we chose not to spend the attempt", recorded as `oversize`. It
            # skips rather than narrows: the cap means "do not spend a call on a
            # corpus this size", so falling back to a narrower one would defeat it.
            # NOTE this is a size heuristic, NOT the hang guard — a corpus well
            # within every provider's context window can still stall; that is what
            # the `timeout` deadline is for.
            if max_prompt_tokens and est_tokens > max_prompt_tokens:
                failed = (f"corpus ~{est_tokens} tokens over the "
                          f"{max_prompt_tokens}-token cap "
                          f"(TRIAGE_SYNTHESIS_MAX_PROMPT_TOKENS)")
                client.usage.record_failure("oversize", failed)
                ui.warn(f"synthesis not attempted — {failed}; pass-1 verdicts "
                        f"stand, chain continues to verify")
                break
            try:
                response = client.complete(
                    synthesize.build_messages(corpus, prompt.text),
                    schema_name="dast_cross_endpoint_synthesis",
                    schema=synthesize.SYNTHESIS_SCHEMA,
                    schema_description=(
                        "Findings visible only across endpoints; never a "
                        "restatement of a single alert."
                    ),
                    max_tokens=synthesize.SYNTHESIS_MAX_TOKENS,
                    pass_name="synthesis",
                    label=f"whole-scan corpus ({endpoint_cap} endpoints)",
                    timeout=deadline,
                )
            except LlmError as exc:
                failed = str(exc)
                client.usage.record_failure(exc.kind, failed)
                # A truncated answer, a corpus over the context window, or an
                # otherwise-unclassified provider error on the whole-corpus call
                # all have the same one lever: fewer endpoints. Try it once, then
                # degrade — a narrower corpus often fits the provider a blind draw
                # landed on (e.g. a 131k-window one that the full corpus overran)
                # where the full corpus did not, salvaging synthesis for the run.
                if exc.kind in ("truncated", "context_overflow",
                                "provider_error") and attempt == 0:
                    ui.warn(f"synthesis {exc.kind} — retrying with a narrower "
                            f"corpus ({synthesize.FALLBACK_MAX_ENDPOINTS} endpoints)")
                    continue
                ui.error(f"synthesis failed, no cross-endpoint findings this run "
                         f"({exc})")
                break
            failed = None
            correlated, dropped = synthesize.collect(response, known_ids)
            ui.found(f"{len(correlated)} cross-endpoint finding(s)"
                     + (f", {dropped} dropped for citing no real finding"
                        if dropped else ""))
            break

        # Further samples of the same corpus, CONCURRENTLY. Each is an
        # independent whole-corpus call, so they are exactly the shape a pool
        # wants — and at ~40-70s apiece, five sequential samples add ~4 minutes
        # of pure waiting to every run.
        #
        # The first call stays sequential above and that is deliberate: it is
        # the one that discovers whether the corpus fits, falling back to a
        # narrower endpoint cap on truncation. The repeats reuse whichever
        # corpus it settled on, so every sample is drawn from the same
        # population — which is what makes them samples rather than variants.
        #
        # The pass-1 invariants hold here for the same reasons and must keep
        # holding: workers touch no shared state (each returns its own claim
        # list), and the result cannot depend on completion order because
        # `merge_repeats` sorts by reproducibility and then by the claim itself.
        # A failed repeat costs its own sample and nothing else.
        produced = [synthesize.Sample(model, correlated)] if not failed else []
        # (model, sample index) for every draw still owed: repeats each, minus
        # the one the discovery call already made for the leading model.
        wanted = [
            (name, index)
            for name in ensemble
            for index in range(1, max(1, repeats) + 1)
            if not (name == model and index == 1)
        ]
        # One client per model — a client is bound to its model — and each keeps
        # its own accounting, folded into the leader's below so the stage still
        # reports one cost. Opened here rather than per sample so an ensemble
        # makes as many clients as it has models, not as it has draws.
        others = {
            name: stack.enter_context(llm_synthesize_client(
                api_key, name, member_provider.get(name, provider)))
            for name in ensemble if name != model
        }
        clients = {model: client, **others}
        # No repeats once the discovery call hard-failed (a timeout, a pre-emptive
        # `oversize` skip, or an un-narrowable overflow): the corpus it just failed
        # on is not worth sampling again, and for a pre-emptive skip firing them
        # would make the calls the cap exists to avoid. A recovered overflow set
        # `failed` back to None, so its repeats still run (on the narrowed corpus).
        if wanted and not failed:
            def _sample(draw: tuple[str, int]):
                name, index = draw
                return name, synthesize.collect(clients[name].complete(
                    synthesize.build_messages(corpus, prompt.text),
                    schema_name="dast_cross_endpoint_synthesis",
                    schema=synthesize.SYNTHESIS_SCHEMA,
                    schema_description=(
                        "Findings visible only across endpoints; never a "
                        "restatement of a single alert."
                    ),
                    max_tokens=synthesize.SYNTHESIS_MAX_TOKENS,
                    pass_name="synthesis",
                    label=f"whole-scan corpus (repeat {index})",
                    timeout=deadline,
                ), known_ids)

            workers = max(1, min(concurrency, len(wanted)))
            ui.step(f"{len(wanted)} further sample(s) across {len(ensemble)} "
                    f"model(s), {workers} in flight")
            with ThreadPoolExecutor(max_workers=workers) as pool:
                futures = {pool.submit(_sample, draw): draw for draw in wanted}
                for future in as_completed(futures):
                    name, index = futures[future]
                    try:
                        _name, (more, more_dropped) = future.result()
                    except LlmError as exc:
                        ui.warn(f"synthesis repeat {index} on {name} failed "
                                f"({exc}) — keeping the samples already collected")
                        continue
                    except Exception as exc:   # never let a worker end the run
                        clients[name].usage.record_failure(
                            "worker_error",
                            f"repeat {index} on {name}: {type(exc).__name__}: {exc}")
                        ui.warn(f"synthesis repeat {index} on {name} failed ({exc})")
                        continue
                    dropped += more_dropped
                    produced.append(synthesize.Sample(name, more))

        if (repeats > 1 or len(ensemble) > 1) and produced:
            correlated = synthesize.merge_samples(produced)
            reproduced = sum(1 for c in correlated
                             if c["reproducibility"]["seen_in"] > 1)
            agreed = sum(1 for c in correlated
                         if c["reproducibility"].get("models_agreeing", 1) > 1)
            ui.found(f"{len(correlated)} distinct claim(s) from "
                     f"{len(produced)}/{len(wanted) + 1} sample(s); {reproduced} seen "
                     "more than once"
                     + (f", {agreed} reached by more than one model"
                        if len(ensemble) > 1 else ""))
        # One cost for the stage; `model_requested` on each logged call keeps
        # which model spent what recoverable.
        for name, other in others.items():
            client.usage.absorb(other.usage)
        usage = client.usage
        # Decoding parameters, recorded per model because this pass alone can run
        # an ensemble — a dropped seed is a per-member fact the way vendor and
        # provider already are. ``temperature``/``seed`` below are the shared
        # constants every member was sent through the one send site
        # (:func:`screening.sampling_params`); the ``*_supported`` maps say
        # whether each served model accepted them, so a seed here is never read
        # as a determinism the run did not have — the same provenance the triage
        # ``llm`` and verify ``loop`` blocks keep for their single model.
        member_capabilities = {
            name: getattr(clients[name], "capabilities", None) for name in ensemble
        }

    return correlated, {
        **prompt.as_metadata(),
        "response_schema": synthesize.SYNTHESIS_SCHEMA,
        "endpoints_in_corpus": len(corpus["endpoints"]),
        "findings_in_corpus": corpus["scan_shape"]["findings_shown"],
        "shared_handlers": len(corpus["shared_handlers"]),
        "max_tokens": synthesize.SYNTHESIS_MAX_TOKENS,
        "repeats": repeats,
        "models": ensemble,
        "temperature": screening.TEMPERATURE,
        "seed": screening.SEED,
        "model_capabilities": member_capabilities,
        "seed_supported": {
            name: (None if caps is None else caps.get("seed"))
            for name, caps in member_capabilities.items()
        },
        "temperature_supported": {
            name: (None if caps is None else caps.get("temperature"))
            for name, caps in member_capabilities.items()
        },
        "concurrency": concurrency,
        "samples_collected": len(produced),
        "dropped_uncited_findings": dropped,
        "failed": failed,
        "usage": usage.as_dict(),
    }


def _model_list(value: str) -> list[str]:
    """``"a, b ,a"`` -> ``["a", "b"]``. Order kept, duplicates dropped.

    Order matters because it is the order samples are drawn in, and a duplicate
    would silently weight one model twice in the agreement count.
    """
    names: list[str] = []
    for raw in str(value or "").split(","):
        name = raw.strip()
        if name and name not in names:
            names.append(name)
    return names


def _provider_list(value: str) -> list[str]:
    """``"pa, ,pc"`` -> ``["pa", "", "pc"]``; ``""`` -> ``[]``.

    Unlike :func:`_model_list` this keeps position and duplicates: a provider
    slug is matched to a model by POSITION (``--synthesis-providers`` ↔
    ``--synthesis-models``), two models may legitimately share one provider, and
    an empty slot means *that* model stays on the routing preference. Only a
    wholly-empty value means "no per-model providers given".
    """
    value = str(value or "").strip()
    if not value:
        return []
    return [p.strip() for p in value.split(",")]


def llm_synthesize_client(api_key: str | None, model: str, provider: str = ""):
    """The synthesis pass uses the same client, and reports its cost separately."""
    return screening.OpenRouterCorrelator(
        api_key=api_key, model=model, provider=provider
    )




__all__ = [
    '_triage_bundle',
    '_triage_calls',
    'triage_config',
    'pass1_candidates',
    'Pass1Plan',
    'plan_pass1',
    'CodeContextUngrounded',
    'require_located_handlers',
    'run_llm_arm',
    'run_synthesis_arm',
    '_model_list',
    '_provider_list',
    'llm_synthesize_client',
]
