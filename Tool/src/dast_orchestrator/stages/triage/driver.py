"""``dast triage`` — argparse plus orchestration for the triage stage.

Reads a finished scan off disk, resolves the run and config, runs the arms, and
writes ``triage.json`` and the printed summary. The thin CLI entry; the judgement
lives in ``arms``. Depends on every other triage submodule.
"""
from __future__ import annotations
import argparse
import json
import os
import sys
import time
from pathlib import Path
from typing import Any
from dast_orchestrator.foundation import config
from dast_orchestrator.context import code_context
from dast_orchestrator.analysis import join
from dast_orchestrator.context import evidence
from dast_orchestrator.analysis import screening
from dast_orchestrator.analysis import oracle as oracle_mod
from dast_orchestrator.adapters import retrieval as retrieval_mod
from dast_orchestrator.analysis import synthesize
from dast_orchestrator.foundation import prompts
from dast_orchestrator.foundation import run_lock
from dast_orchestrator.foundation import run_paths
from dast_orchestrator.adapters import targets
from dast_orchestrator.foundation import ui
from dast_orchestrator.foundation import metrics as run_metrics
from dast_orchestrator.analysis.join import Bundle, JoinError
from dast_orchestrator.analysis.screening import LlmError
from .common import *
from .arms import *

def print_summary(artifact: dict[str, Any]) -> None:
    """One section: what triage was given on the left, what it produced on the
    right, so the move from alerts to findings to flags reads at a glance.

    The individual findings and the raw join/source breakdowns are in
    ``triage.json``; the feed is the delta, not the roster. The scan-context
    caveats (a passive-only scan, one rule dominating the alerts) stay as
    warnings under the columns, because they change how every number above is
    read.
    """
    summary = artifact["summary"]
    total = summary["raw_alerts"]
    asked = summary["llm_findings_asked"]

    left = [
        f"{total} alerts",
        f"{summary['findings']} findings / {summary['bundles']} endpoints",
        f"{summary['bundles_with_static_context']} with Noir context",
    ]
    right = [f"{summary['deterministic_rescans']} flagged · deterministic"]
    if asked:
        right.append(f"{summary['llm_rescans']} flagged · llm ({asked} asked)")
        right.append(f"{summary['correlated_synthesis_findings']} cross-endpoint")
        agreement = {k: v for k, v in sorted(summary["agreement"].items())
                     if k not in (join.NOT_SENT, join.ASKED_NO_VERDICT)}
        if agreement:
            right.append(f"agreement {agreement}")

    phase = ui.open_phase("Triage summary")
    ui.two_columns("in", "out", left, right)

    rules = summary.get("top_rules") or []
    if rules:
        ui.item("noisiest rule",
                f"{rules[0]['plugin_id']} {rules[0]['name'][:40]} "
                f"({rules[0]['alerts']}, {rules[0]['risk']})")

    active = summary["alerts_by_zap_source"].get("active-scanner", 0)
    if total and active / total < 0.05:
        # Deliberately does NOT presuppose the cause: triage reads the finished
        # artifacts and cannot see whether the active scan was cut off by its cap
        # or completed and found nothing (the scan stage records that as
        # `truncated_by_cap` in scan-metrics.json, and warns about a
        # cap-starved scan itself). Telling the reader to "raise the cap" when the
        # scan actually completed — as on the first Grafana run — is wrong advice.
        ui.warn(f"only {active} of {total} alerts came from the active scanner — "
                "these results are essentially a passive scan. Check the scan's "
                "`truncated_by_cap`: if the active scan was cut off, raise "
                "--max-active-scan-minutes; if it completed, the reachable "
                "attack surface is simply small. Either way, do not read an "
                "injection/traversal detection rate into a passive result.")
    if rules and total and rules[0]["alerts"] / total > 0.5:
        ui.warn(f"rule {rules[0]['plugin_id']} alone is "
                f"{rules[0]['alerts'] / total * 100:.0f}% of all alerts — quote the "
                "active/passive split only together with this, since one noisy "
                "rule can make a thin scan look productive.")
    if asked:
        consistency = summary.get("llm_self_consistency") or {}
        if consistency.get("shared_handler_comparisons"):
            for example in consistency.get("shared_handler_examples", [])[:3]:
                ui.warn(f"rule {example['rule']} judged both ways on "
                        f"{example['routes'][0]} and {example['routes'][1]} — "
                        "same handler, so the reasoning must name what differs")
        unanswered = summary["llm_findings_unanswered"]
        if unanswered:
            share = unanswered / asked * 100
            ui.warn(f"{unanswered} of {asked} findings put to the model "
                    f"({share:.0f}%) came back with no verdict — they are neither "
                    "judged nor unexamined, and the agreement counts cover only "
                    "the answered ones.")
        synthesis = artifact.get("synthesis") or {}
        if synthesis.get("dropped_uncited_findings"):
            ui.warn(f"{synthesis['dropped_uncited_findings']} synthesis finding(s) "
                    "dropped for citing no real finding_id")
    phase.close(timed=False)

    if summary["llm_findings_asked"]:
        print_model_usage(artifact)


def print_model_usage(artifact: dict[str, Any]) -> None:
    """Report what the whole LLM arm cost, both passes together.

    Reported as a **total** because that is the number the CI question asks —
    "what does triaging this scan cost" — and because the per-pass figures
    invite an undercount: pass 1 is the loud one, so a single "Model usage" line
    carrying only its cost reads as the run's cost while quietly omitting
    synthesis. The per-pass split is printed underneath, since the two passes are
    priced very differently per call and the writeup compares them.
    """
    passes = [
        ("pass 1 (triage)", (artifact.get("llm") or {}).get("usage") or {}),
        ("pass 2 (synthesis)", (artifact.get("synthesis") or {}).get("usage") or {}),
    ]
    present = [(name, u) for name, u in passes if u]
    if not present:
        return

    def total(key: str) -> float:
        return sum(float(u.get(key, 0) or 0) for _n, u in present)

    cost = ui.open_phase("Model usage — both passes")
    ui.item("calls", int(total("calls")))
    ui.item("tokens", f"{int(total('prompt_tokens'))} prompt + "
                      f"{int(total('completion_tokens'))} completion")
    ui.item("cost", f"${total('cost_usd'):.4f}")
    ui.item("failed / retried",
            f"{int(total('failed_calls'))} / {int(total('retried_calls'))}")
    for name, usage in present:
        ui.item(f"  {name}", f"{usage.get('calls', 0)} calls, "
                             f"${float(usage.get('cost_usd', 0) or 0):.4f}"
                             + (f", failures {usage['failure_kinds']}"
                                if usage.get("failure_kinds") else ""))
    cost.close()


def dry_run(bundles: list[Bundle], findings: list[dict[str, Any]],
            out_dir: Path, timestamp: str, scan_summary: dict[str, Any] | None = None,
            pass1_context: str = screening.DEFAULT_PASS1_CONTEXT,
            assembler: "evidence.Assembler | None" = None,
            synthesis_calls: int = 1,
            oracle_target: "targets.Target | None" = None,
            prune_noninteractive_php: bool = False,
            max_alerts_per_call: int = screening.MAX_ALERTS_PER_CALL,
            max_unmatched_findings: int = config.NO_LIMIT) -> Path:
    """Write exactly what both LLM passes would send, without sending anything.

    Covers pass 2 as well as pass 1: the synthesis corpus is the larger single
    request and the one whose size decides whether the run still fits in one
    call, so a dry run that omitted it would answer the cheaper question only.

    :param pass1_context: must be the level the live run would use, or the
        prompts written here are not the prompts that would be sent — which is
        the one thing a dry run exists to guarantee.
    """
    # Each pass gets its OWN oracle block: same facts, different instruction.
    # Writing the triage instruction into the synthesis prompt would make the
    # dry run misreport the one thing it exists to show — what would be sent.
    oracle = oracle_mod.block(oracle_target, "screening") if oracle_target else None
    oracle_synthesis = (oracle_mod.block(oracle_target, "synthesis")
                        if oracle_target else None)
    candidates, _pruned = join.select_llm_candidates(
        bundles, prune_noninteractive_php)
    cross_context = screening.build_cross_endpoint_context(bundles, pass1_context)
    if assembler is not None:
        assembler.prepare(candidates)
    # Planned and chunked exactly as the live arm would send them (the limit and
    # the systemic fold included), so the call count and the token estimate
    # describe the run that would actually happen.
    plan = plan_pass1(candidates, findings, max_unmatched_findings,
                      assembler.has_source if assembler is not None else None)
    payloads = []
    for bundle, pairs in plan.work:
        chunks = screening.chunk_alerts(pairs, max_alerts_per_call)
        for chunk_no, chunk in enumerate(chunks, start=1):
            payloads.append(
                {
                    "endpoint": bundle.identifier,
                    "chunk": f"{chunk_no}/{len(chunks)}",
                    "alerts_in_chunk": len(chunk),
                    "messages": screening.build_messages(
                        bundle, chunk, cross_context.get(bundle.identifier),
                        assembler=assembler, oracle=oracle,
                    ),
                }
            )
    chars = sum(len(m["content"]) for p in payloads for m in p["messages"])

    # The pass-1 system prompt is identical for every call — it is the cacheable
    # header, `screening.SYSTEM_PROMPT`, and pass 1 shares only it (see the
    # cache-hit comment below). So the dump stores it ONCE and each call keeps
    # only the turn that differs (the per-endpoint user payload), rather than
    # repeating the header per endpoint. `chars` above still counts the full
    # messages, because the live run really does send the system prompt on every
    # pass-1 call — deduping the dump changes what the file repeats, never the
    # cost it estimates.
    pass1_system = payloads[0]["messages"][0]["content"] if payloads else None
    pass1_calls = [
        {**p, "messages": [m for m in p["messages"] if m["role"] != "system"]}
        for p in payloads
    ]

    synthesis: dict[str, Any] | None = None
    if scan_summary is not None:
        corpus = synthesize.build_corpus(bundles, findings, scan_summary,
                                             oracle=oracle_synthesis)
        messages = synthesize.build_messages(corpus)
        chars += sum(len(m["content"]) for m in messages)
        synthesis = {
            "endpoints": len(corpus["endpoints"]),
            "findings": corpus["scan_shape"]["findings_shown"],
            "shared_handlers": len(corpus["shared_handlers"]),
            "messages": messages,
        }

    path = run_paths.RunLayout(out_dir, timestamp).ensure().path(
        run_paths.TRIAGE_PROMPTS
    )
    path.write_text(
        json.dumps(
            {
                "pass1_screening": {"system": pass1_system, "calls": pass1_calls},
                "pass2_synthesis": synthesis,
            },
            indent=2,
        )
    )
    # `synthesis_calls`, not "1": repeats and the model ensemble both multiply
    # pass 2, and a plan that under-reports the count under-reports the cost the
    # dry run exists to let someone estimate. The corpus is identical across
    # them, so the prompt is written once and the count says how often it goes.
    print(f"Dry run: pass 1 = {len(plan.work)} endpoints in {len(payloads)} calls, "
          f"{plan.deferred_note()} by the limit; "
          f"pass 2 = {synthesis_calls} call(s) over "
          f"{(synthesis or {}).get('endpoints', 0)} endpoints"
          + (" (identical corpus each time)" if synthesis_calls > 1 else ""))
    print(f"  ~{chars // 4} prompt tokens total, nothing sent")
    print("  (multiply by your model's input price for the cost; the live run "
          "reports OpenRouter's own figure)")
    print(f"Prompts written to {path}")
    return path


def build_parser() -> argparse.ArgumentParser:
    """This stage's argument parser, built without parsing anything.

    Separate from :func:`main` so ``dast`` can read the flags this stage
    accepts — that is what lets one flag be routed to the right stage of a
    sequence, and an ambiguous one be refused by name rather than silently
    applied to the wrong stage. Defaults still come from the environment, so
    the caller loads the stage's env file first.
    """
    pre = argparse.ArgumentParser(add_help=False)
    config.add_env_flags(pre, "triage")
    # The user-facing package docstring, not this driver's developer docstring —
    # the SAME source `dast commands` renders, so --help and COMMANDS.md agree.
    from dast_orchestrator.stages import triage as _pkg
    parser = argparse.ArgumentParser(
        description=config.command_description(_pkg.__doc__), parents=[pre])
    parser.add_argument(
        "run", metavar="<run_id>",
        help=run_paths.RUN_ARG_HELP.format(
            verb="triage", default="the newest run with both scan artifacts"),
    )
    parser.add_argument("--data-dir", type=Path, default=DATA_DIR)
    parser.add_argument(
        "--concurrency", type=int,
        default=int(config.default_for("TRIAGE_CONCURRENCY")),
        help="Pass-1 calls in flight at once. The calls are independent by "
             "design, so this is pure wall-clock: 1 is sequential and the "
             "result is identical either way.\n"
             "Lower it if a provider rate-limits; raise it only against a model "
             "served by several.",
    )
    parser.add_argument(
        "--max-alerts-per-call", dest="max_alerts_per_call", type=int,
        default=int(config.default_for("TRIAGE_MAX_ALERTS_PER_CALL")),
        help="Starting number of an endpoint's alerts asked about in one pass-1 "
             "call (chunked, never dropped). Smaller batches trade more calls for "
             "fewer re-asks when a provider returns a short verdict list; the "
             "optimum is provider-dependent, so it is measured, not fixed. "
             "Env: TRIAGE_MAX_ALERTS_PER_CALL.",
    )
    parser.add_argument(
        "--peer-context", dest="peer_context",
        choices=screening.PASS1_CONTEXT_LEVELS,
        default=config.default_for("TRIAGE_PEER_CONTEXT"),
        help="How much each per-endpoint (pass-1) call is told about its PEER "
             "endpoints — where else in THIS scan the same rule fired: `none` "
             "(one endpoint per call), `peers` (those peer endpoints), `full` "
             "(plus which of them run the same handler). Without it pass 1 "
             "cannot know it judged the same rule differently next door; `none` "
             "keeps that measurable.\n"
             "Distinct from verify's route `siblings` and from pass 2's "
             "cross-endpoint findings.",
    )
    parser.add_argument(
        "--http-context",
        default=config.default_for("TRIAGE_HTTP_CONTEXT"),
        help="How much of each finding's HTTP exchange reaches the prompt — "
             "the config/excerpts/<name>.yml to use: none / minimal / balanced "
             "/ maximum. Storage is generous and excerpting strict, so this is "
             "the knob that trades tokens against evidence.\n"
             "The chosen policy file travels verbatim in the artifact.",
    )
    parser.add_argument(
        "--code-context",
        choices=code_context.CODE_CONTEXT_LEVELS,
        default=config.default_for("TRIAGE_CODE_CONTEXT"),
        help="How much handler SOURCE each pass-1 call gets: `none` (the A/B "
             "baseline, not a fallback), `handler` (the resolved handler plus "
             "its hop bodies), `handler+trace` (that source plus the call chain "
             "followed and where the flagged parameter literally appears).\n"
             "Depth is set by --code-context-hops, the per-endpoint line "
             "ceiling by --code-context-lines.",
    )
    parser.add_argument(
        "--code-context-hops", type=int,
        default=int(config.default_for("TRIAGE_CODE_CONTEXT_MAX_HOPS")),
        help="How many call hops out from the handler to include.\n"
             "The walk saturates after one hop — calls that would go further "
             "leave the indexed handler tree. Applies to --code-context handler "
             "and handler+trace.",
    )
    parser.add_argument(
        "--code-context-lines", type=int,
        default=int(config.default_for("TRIAGE_CODE_CONTEXT_MAX_LINES")),
        help="Ceiling on source lines per endpoint. Breadth-first, so what a "
             "full budget drops is always further from the handler than what it "
             "kept.\n"
             "Bounds the source that --code-context handler/handler+trace emit.",
    )
    parser.add_argument(
        "--retrieval",
        choices=retrieval_mod.RETRIEVAL_MODES,
        default=config.default_for("TRIAGE_RETRIEVAL"),
        help="How pass 1 gets its evidence: `push` (the assembler attaches the "
             "exchange and the handler source to every prompt — the A/B "
             "baseline) or `pull` (a minimal pack plus a manifest of what is "
             "retrievable, and the model asks the read-only context MCP server "
             "for what it needs).\n"
             "`pull` is bounded by --retrieval-max-calls.",
    )
    parser.add_argument(
        "--retrieval-max-calls", type=int,
        default=int(config.default_for("TRIAGE_RETRIEVAL_MAX_CALLS")),
        help="Retrievals one pass-1 call may make before the tools are "
             "withdrawn and the model must answer. Deliberately small: the "
             "question is whether a model asks for the RIGHT evidence, and a "
             "generous budget answers a different one.\n"
             "Only meaningful with --retrieval pull.",
    )
    # A pair, one dest: `--no-llm` is what a person types, `TRIAGE_LLM_ENABLED` is what
    # a harness sheet sets — and a sheet has to be able to say "control arm
    # only", since that is the free, key-less mode this project leans on.
    parser.add_argument(
        "--prompt-cache-triage", dest="prompt_cache_triage", action="store_true",
        default=config.default_for("TRIAGE_PROMPT_CACHE").strip().lower()
        not in ("0", "false", "no", "off"),
        help="Mark pass 1's system prompt as a cacheable prefix. Worth little "
             "here — pass 1's many small calls share only a small header, so "
             "little caches.\n"
             "Separately switchable so the writeup's claim that this site is "
             "NOT where caching pays stays measurable. --no-prompt-cache-triage "
             "is the off form.",
    )
    parser.add_argument(
        "--no-prompt-cache-triage", dest="prompt_cache_triage",
        action="store_false", help="Off form of --prompt-cache-triage.",
    )
    parser.add_argument(
        "--prompt-cache-retrieval", dest="prompt_cache_retrieval",
        action="store_true",
        default=config.default_for("TRIAGE_PROMPT_CACHE_RETRIEVAL").strip().lower()
        not in ("0", "false", "no", "off"),
        help="Mark the pull-mode retrieval loop's stable prefix as cacheable. "
             "The one site where caching could change a CONCLUSION rather than a "
             "bill: pull is a tool-use loop that re-sends the whole conversation "
             "each turn, so it spends far more prompt tokens.\n"
             "Applies only with --retrieval pull. --no-prompt-cache-retrieval "
             "is the off form.",
    )
    parser.add_argument(
        "--no-prompt-cache-retrieval", dest="prompt_cache_retrieval",
        action="store_false", help="Off form of --prompt-cache-retrieval.",
    )
    parser.add_argument(
        "--prompt-cache", dest="prompt_cache", action="store_true",
        default=config.default_for("SHARED_PROMPT_CACHE").lower() not in ("0", "false", "no", "off"),
        help="Mark a cacheable stable prefix on the multi-turn calls. Caching "
             "changes no output — a hit returns the tokens the model would have "
             "computed anyway. Synthesis and the verification loop cache heavily "
             "(they re-send a large stable prefix); pass 1 barely does.\n"
             "--no-prompt-cache is the off form, for pricing the saving.",
    )
    parser.add_argument(
        "--no-prompt-cache", dest="prompt_cache", action="store_false",
        help="Send every prompt uncached, the off form of --prompt-cache, for "
             "the cost comparison.",
    )
    parser.add_argument(
        "--stage-max-cost", type=float, default=float(config.default_for("SHARED_STAGE_MAX_COST_USD")),
        help="Ceiling on what THIS stage's model calls may cost, in USD; -1 "
             "removes the ceiling. Reaching it stops further calls; findings "
             "already put to the model stay recorded as asked-but-unanswered, "
             "not passed off as judged.\n"
             "Per-stage; --run-max-cost bounds the whole run.",
    )
    parser.add_argument(
        "--run-max-cost", type=float, default=float(config.default_for("SHARED_RUN_MAX_COST_USD")),
        help="Ceiling on what the whole RUN may cost across all its stages, in "
             "USD; -1 removes it. Measured against this run's existing metrics "
             "records, so a second stage inherits the first's spend.\n"
             "Run-wide; --stage-max-cost bounds this stage alone.",
    )
    parser.add_argument(
        "--no-llm", dest="use_llm", action="store_false",
        default=config.env_bool("TRIAGE_LLM_ENABLED", True),
        help="Run the control arm only: the deterministic rescan table, no API "
             "key and no spend.\n"
             "The off form of --use-llm.",
    )
    parser.add_argument(
        "--use-llm", dest="use_llm", action="store_true",
        help="Run the LLM arm alongside the control arm.\n"
             "The explicit on form of --no-llm, so an env file or a sheet row "
             "can set it either way without a flag.",
    )
    parser.add_argument(
        "--screening-prompt", default=config.default_for("TRIAGE_PROMPT_VERSION"),
        help="Which prompts/screening/screening.v<N>.md to send (pass 1). Pin one "
             "to keep a comparison valid when a newer prompt lands — two sheet "
             "rows differing only here is a prompt A/B.\n"
             "Falls back to the newest version on disk.",
    )
    parser.add_argument(
        "--synthesis-prompt", default=config.default_for("TRIAGE_SYNTHESIS_PROMPT_VERSION"),
        help="Which prompts/synthesis/synthesis.v<N>.md to send.\n"
             "Falls back to the newest version on disk.",
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        default=config.env_bool("TRIAGE_DRY_RUN"),
        help="Write the prompts that would be sent and stop, spending nothing.\n"
             "Set it via the env only deliberately — it turns a real run into a "
             "no-op.",
    )
    parser.add_argument(
        "--oracle", action="store_true",
        default=config.env_bool("SHARED_ORACLE"),
        help="Oracle-guided mode: hand every LLM stage the target's documented "
             "vulnerabilities (targets/<name>/oracle.md) and measure how much "
             "it still confirms. An upper bound on what this architecture could "
             "detect WITH perfect prior knowledge — never a detection rate, "
             "never in the same table as a blind run.\n"
             "Shared with verify so the whole chain runs guided or blind, never "
             "half; the gap to a blind run sizes the 'detectable but missed' "
             "set.",
    )
    parser.add_argument(
        "--out-suffix", dest="out_suffix",
        default="",
        help="Suffix the output artifact: triage-<ts>-<suffix>.json. Keeps "
             "a model-comparison run alongside the baseline instead of "
             "replacing it.\n"
             "verify reads it back with --in-suffix; shared with verify/report "
             "so a suffixed variant flows through the chain.",
    )
    parser.add_argument(
        "--no-synthesis", dest="use_synthesis", action="store_false",
        default=config.env_bool("TRIAGE_SYNTHESIS_ENABLED", True),
        help="Skip the cross-endpoint synthesis pass (pass 2); pass-1 triage "
             "still runs. One extra call per run, so this isolates the passes "
             "rather than saving cost.\n"
             "The off form of --synthesis.",
    )
    parser.add_argument(
        "--synthesis", "--use-synthesis", dest="use_synthesis", action="store_true",
        help="Run the cross-endpoint synthesis pass (pass 2).\n"
             "The explicit on form of --no-synthesis, so an env file or a sheet "
             "row can set it either way without a flag.",
    )
    parser.add_argument(
        "--prune-noninteractive-php", dest="prune_noninteractive_php",
        action="store_true", default=config.env_bool("TRIAGE_PRUNE_NONINTERACTIVE_PHP"),
        help="Drop php_pure endpoints under cli/ from the LLM arm — a "
             "framework-less PHP app's (Cacti's) command-line scripts, which "
             "reject HTTP and so only ever carry passive findings on a surface no "
             "client reaches. Cuts the corpus the model iterates on; the "
             "deterministic record still sees every endpoint.\n"
             "cli/ only (install/ was validated out — the installer is reachable "
             "and carries rescan-flagged findings). Off by default and off the "
             "WordPress path, where php_pure is dropped wholesale at scan time.",
    )
    parser.add_argument(
        "--max-endpoints", type=int,
        default=int(config.default_for("TRIAGE_MAX_ENDPOINTS")),
        help="Cap the number of pass-1 model calls; 0 removes the cap. For cost "
             "control while iterating on the prompt.",
    )
    parser.add_argument(
        "--max-unmatched-findings", dest="max_unmatched_findings", type=int,
        default=int(config.default_for("TRIAGE_MAX_UNMATCHED_FINDINGS")),
        help="How many findings beyond the old gate pass 1 asks. Every finding of "
             "an endpoint with static context is asked; the rest are ranked by ZAP "
             "risk, then source before none, and the first N asked, the others "
             "recorded as deferred. 0 asks the old gate only; -1 asks every "
             "finding. A scope, fixed before any call, so a repeat asks the same.",
    )
    parser.add_argument(
        "--screening-max-minutes", dest="screening_max_minutes", type=int,
        default=int(config.default_for("TRIAGE_SCREENING_MAX_MINUTES")),
        help="Wall-clock limit on pass 1: no call starts after it, and each unsent "
             "call is recorded as a time_limit failure. A safety net set well above "
             "a normal run, not a scope; -1 removes it.",
    )
    parser.add_argument(
        "--force", action="store_true",
        help="Override this stage's two refusals: the lock another process "
             "holds on the run directory, and overwriting an artifact that "
             "already contains LLM results with a control-arm-only run (which "
             "would discard paid model output).",
    )
    parser.add_argument(
        "--screening-model", default=config.default_for("TRIAGE_SCREENING_MODEL"),
        help="The model for pass 1 (screening: per-endpoint triage). Many small calls, so "
             "unit price and latency dominate and reasoning is a liability — it "
             "is billed from the completion budget and causes truncation "
             "splits.\n"
             "Empty falls back to the pinned pass-1 default. Set per pass — pass "
             "2 has its own --synthesis-model.",
    )
    parser.add_argument(
        "--synthesis-model", default=config.default_for("TRIAGE_SYNTHESIS_MODEL"),
        help="The model for pass 2 (cross-endpoint synthesis). A handful of "
             "calls per run, so unit price barely matters and one long chain of "
             "reasoning is everything — the one stage where an expensive model "
             "is affordable.\n"
             "Empty falls back to its own pinned default. Use --synthesis-models "
             "for an ensemble.",
    )
    parser.add_argument(
        "--synthesis-models", default=config.default_for("TRIAGE_SYNTHESIS_MODELS"),
        help="Comma-separated models to draw pass-2 samples from, an ENSEMBLE. "
             "Each named model draws --synthesis-repeats samples of the same "
             "corpus, so the union reports both per-model recurrence and how "
             "many MODELS reached each claim — the stronger signal, since "
             "repeats of one model share its failure modes.\n"
             "Total pass-2 calls is repeats x models, multiplying the pass's "
             "cost. Empty falls back to the single --synthesis-model.",
    )
    parser.add_argument(
        "--screening-provider", default=config.default_for("TRIAGE_SCREENING_PROVIDER"),
        help="Hard-pin the OpenRouter provider (a slug, or a comma list) for the "
             "pass-1 (screening) model — the sibling of --screening-model. "
             "A value routes to exactly those providers with fallbacks off (fully "
             "reproducible); empty (the default) uses the throughput/"
             "require-parameters preference.",
    )
    parser.add_argument(
        "--synthesis-provider", default=config.default_for("TRIAGE_SYNTHESIS_PROVIDER"),
        help="Provider for the pass-2 (synthesis) model — the sibling of "
             "--synthesis-model. Also the default for every --synthesis-models "
             "ensemble member, unless --synthesis-providers pins them "
             "individually. A value hard-pins with fallbacks off; empty = the "
             "throughput/require-parameters preference.",
    )
    parser.add_argument(
        "--synthesis-providers", default=config.default_for("TRIAGE_SYNTHESIS_PROVIDERS"),
        help="Providers for the --synthesis-models ensemble, matched to it BY "
             "POSITION (providers[i] pins models[i]); an empty slot (`a,,c`) "
             "leaves that model on the routing preference. A single provider "
             "cannot serve models from different vendors, so this is how a "
             "heterogeneous ensemble is pinned reproducibly. Its count must equal "
             "--synthesis-models' — a mismatch prints an error and SKIPS "
             "synthesis (pass 1 is unaffected). Empty (the default) leaves every "
             "member on --synthesis-provider.",
    )
    parser.add_argument(
        "--synthesis-repeats", type=int,
        default=synthesize.DEFAULT_REPEATS, help="How many independent whole-corpus synthesis calls to make, "
             "unioned by the evidence each claim cites. Sampling, not chunking "
             "— every repeat sees the entire scan, and more repeats surface a "
             "reproducible claim more reliably.\n"
             "Each claim carries how many samples produced it, which separates "
             "a result from a lead. Multiplied by --synthesis-models.",
    )
    parser.add_argument(
        "--synthesis-timeout-seconds", type=float,
        default=config.default_for("TRIAGE_SYNTHESIS_TIMEOUT_SECONDS"),
        help="Per-call wall-clock deadline for a synthesis request, in seconds. "
             "Set above the slowest completing call ever observed on the frozen "
             "model (~59min on a slow provider; p90 ~2min), so it never cuts "
             "normal function on any target — it exists only to bound a genuine "
             "stall, a provider that accepts the request and never answers.\n"
             "On expiry the pass is SKIPPED (recorded as a 'timeout' failure), "
             "pass-1 verdicts stand, and the chain continues to verify. 0 "
             "disables the deadline.",
    )
    parser.add_argument(
        "--synthesis-max-prompt-tokens", type=int,
        default=config.default_for("TRIAGE_SYNTHESIS_MAX_PROMPT_TOKENS"),
        help="Pre-emptive synthesis cap: skip the whole-corpus pass WITHOUT "
             "attempting it when its estimated prompt exceeds this many tokens. "
             "0 (the default) disables it — synthesis is always attempted.\n"
             "An opt-in size heuristic for a corpus known not to be worth a call; "
             "recorded distinctly as an 'oversize' skip. NOT the stall guard (a "
             "within-window corpus can still hang) — that is "
             "--synthesis-timeout-seconds.",
    )
    config.add_targets_dir_flag(parser)
    config.normalize_metavars(parser)
    return parser


@run_lock.guarded
def main(argv: "list[str] | None" = None) -> int:
    pre = argparse.ArgumentParser(add_help=False)
    config.add_env_flags(pre, "triage")
    known, _ = pre.parse_known_args(argv)
    env = config.load_stage_env("triage", known.env_file)

    parser = build_parser()
    args = parser.parse_args(argv)
    overridden = config.apply_explicit_overrides(env, args, parser, argv)
    os.environ["SHARED_PROMPT_CACHE"] = "1" if args.prompt_cache else "0"
    os.environ["TRIAGE_PROMPT_CACHE"] = "1" if args.prompt_cache_triage else "0"
    os.environ["TRIAGE_PROMPT_CACHE_RETRIEVAL"] = "1" if args.prompt_cache_retrieval else "0"
    if overridden:
        ui.warn(f"{ui.short_path(known.env_file)} supplies (no flag given): "
                f"{', '.join(sorted(overridden))}")

    # Point target discovery and source resolution at the configured dir before
    # the scan target is looked up by URL below.
    targets.use_dir(args.targets_dir)

    try:
        run = join.load_run(args.data_dir, args.run)
    except JoinError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    # Before the first prompt is assembled and before a key is touched: this
    # stage's whole cost is the arm it is about to run. Released by
    # `@run_lock.guarded` however this returns.
    run_lock.claim(
        run_paths.RunLayout(args.data_dir, run.timestamp).dir,
        "triage", args.out_suffix, force=args.force,
    )

    # Resolved before anything runs: an unknown prompt version must not surface
    # after the join, halfway into a paid pass.
    try:
        screening_prompt = prompts.load("screening", args.screening_prompt)
        synthesis_prompt = prompts.load("synthesis", args.synthesis_prompt)
    except prompts.PromptError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    # One assembler per run, built before anything is sent: it is what decides
    # what "the evidence" is for every prompt in this stage, and it must not be
    # rebuilt per call. Failures here degrade the level and warn; see
    # `evidence.assembler_for_run`.
    scan_target = targets.for_url(str(run.zap_report.get("target") or ""))
    assembler = evidence.assembler_for_run(
        run.zap_report,
        run_paths.RunLayout(args.data_dir, run.timestamp).path(
            run_paths.ZAP_MESSAGES),
        excerpt_policy=args.http_context,
        code_level=args.code_context,
        target=scan_target,
        source_dir=targets.target_source(scan_target),
        max_hops=args.code_context_hops,
        max_lines=args.code_context_lines,
        retrieval_mode=args.retrieval,
    )

    # Resolved before anything is sent, so `--ceiling` against a target with no
    # oracle document fails immediately rather than after the money is spent —
    # a run that silently went blind would still be labelled a ceiling.
    if args.oracle:
        try:
            oracle_mod.require(scan_target)
        except oracle_mod.OracleError as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            return 2

    seed_map_note = (
        run.seed_map_path.name
        if run.seed_map_path
        else "MISSING (scan predates the seed map; regex tier only)"
    )
    ui.headline(f"Triage · {'both arms' if args.use_llm else 'deterministic'}",
                f"run {run.timestamp}  →  {run.zap_report_path.parent}")
    inputs = ui.open_phase("Inputs")
    ui.item("alerts", run.zap_report_path.name)
    ui.item("ai-context", run.ai_context_path.name)
    ui.item("seed-map", seed_map_note)
    # Each pass sets its OWN model and provider — there is no bare "sets both"
    # flag (it never actually set both, and was one flag too many). Pass 1 is
    # --screening-model/--screening-provider, pass 2 --synthesis-model/-provider; each
    # empty setting falls back to its own pinned default / the routing preference.
    screening_model = args.screening_model or screening.MODEL
    synthesis_model = args.synthesis_model or synthesize.SYNTHESIS_MODEL
    triage_provider = args.screening_provider
    synthesis_provider = args.synthesis_provider
    # Pass-2 ensemble providers are matched to --synthesis-models by position; a
    # single provider cannot serve models from different vendors. A count that
    # does not line up is a configuration error the run cannot silently paper
    # over, so it is reported and pass 2 is skipped — pass 1 still stands.
    synthesis_providers = _provider_list(args.synthesis_providers)
    _synthesis_members = _model_list(args.synthesis_models)
    if synthesis_providers and len(synthesis_providers) != len(_synthesis_members):
        print(f"ERROR: --synthesis-providers ({len(synthesis_providers)}) does not "
              f"match --synthesis-models ({len(_synthesis_members)}); they pin "
              "models by position. Skipping synthesis (pass 1 is unaffected).",
              file=sys.stderr)
        args.use_synthesis = False
    ui.item("pass 1 model", screening_model if args.use_llm else "none (--no-llm)")
    ui.item("pass 2 model", synthesis_model if args.use_llm else "none (--no-llm)")
    if args.oracle:
        # Loud, and on every ceiling run. The whole risk of this mode is that
        # its numbers are read as detection numbers by whoever opens the
        # artifact next.
        ui.warn(
            "ORACLE-GUIDED (--ceiling): both passes are being told this "
            f"target's documented vulnerabilities "
            f"({oracle_mod.path_for(scan_target)}) before they judge anything. "
            "What comes out is an upper bound on what this pipeline could find "
            "WITH prior knowledge — it is NOT a detection rate and must never "
            "share a table with a blind run."
        )
    inputs.close(timed=False)

    # A run-wide ceiling is enforced against what the *run* has already spent,
    # which only the metrics records on disk know — the stages are separate
    # processes, which is exactly why the number cannot be carried in memory.
    spent_before = run_metrics.run_cost_so_far(
        args.data_dir, run.timestamp, args.out_suffix)

    metrics = run_metrics.RunMetrics(run.timestamp, kind="triage", label=args.out_suffix)
    metrics.record_config(triage_config(
        screening_model=screening_model if args.use_llm else "",
        synthesis_model=(
            synthesis_model if (args.use_llm and args.use_synthesis) else ""
        ),
        screening_prompt_version=screening_prompt.version if args.use_llm else None,
        synthesis_prompt_version=(
            synthesis_prompt.version
            if (args.use_llm and args.use_synthesis) else None
        ),
        synthesis_repeats=(
            args.synthesis_repeats
            if (args.use_llm and args.use_synthesis) else None
        ),
        # An ensemble is a different experiment from one model sampled N times,
        # so the run id has to say which was run.
        synthesis_models=(
            ",".join(_model_list(args.synthesis_models))
            if (args.use_llm and args.use_synthesis) else ""
        ),
        # The provider PREFERENCE each pass was configured with. Recorded beside
        # the model: which provider a call was routed to changes its cost and can
        # change its behaviour, and the resolved config must say what was asked
        # for (the provider that actually SERVED each call is logged per-call).
        screening_provider=args.screening_provider if args.use_llm else "",
        synthesis_provider=(
            args.synthesis_provider if (args.use_llm and args.use_synthesis) else ""
        ),
        synthesis_providers=(
            args.synthesis_providers
            if (args.use_llm and args.use_synthesis) else ""
        ),
        rescan_table_version=join.rescan_table.RESCAN_TABLE_VERSION,
        concurrency=args.concurrency if args.use_llm else None,
        # How many alerts ride in one pass-1 call — the chunk size that shapes the
        # run's call pattern and its token/cost profile.
        max_alerts_per_call=args.max_alerts_per_call if args.use_llm else None,
        pass1_context=args.peer_context if args.use_llm else "",
        # Both describe what the prompt CONTAINED without changing the prompt
        # file, so two runs differing only here are different experiments and
        # the run id has to say so.
        excerpt_policy=assembler.policy.name if args.use_llm else "",
        code_context=assembler.code_level if args.use_llm else "",
        code_context_hops=(
            args.code_context_hops if args.use_llm and assembler.code_enabled
            else None
        ),
        code_context_lines=(
            args.code_context_lines if args.use_llm and assembler.code_enabled
            else None
        ),
        # Which side of the pull-vs-push A/B this run is, in the run's own
        # identity: two artifacts over one corpus that differ only here are
        # different experiments, and a digest that could not tell them apart
        # would let one be reported as the other.
        retrieval=args.retrieval if args.use_llm else "",
        retrieval_max_calls=(
            args.retrieval_max_calls
            if args.use_llm and args.retrieval == retrieval_mod.PULL_MODE
            else None
        ),
        # Which population pass 1 asks: the old gate, plus up to this many
        # findings beyond it by risk (-1 all). In the digest, so runs that asked
        # different populations are never one corpus; `include_unmatched` keeps
        # its meaning for stored runs (any finding beyond the old gate asked).
        include_unmatched=args.max_unmatched_findings != 0,
        max_unmatched_findings=(args.max_unmatched_findings
                                if args.use_llm else None),
        screening_max_minutes=(args.screening_max_minutes
                               if args.use_llm and args.screening_max_minutes >= 0
                               else None),
        # Off by default and only meaningful on a php_pure target (Cacti); in the
        # digest so a pruned run and a full one over the same scan are told apart.
        prune_noninteractive_php=args.prune_noninteractive_php or None,
        max_endpoints=args.max_endpoints or None,
        max_cost_usd=args.stage_max_cost if args.stage_max_cost >= 0 else None,
        run_max_cost_usd=args.run_max_cost if args.run_max_cost >= 0 else None,
        prompt_cache=args.prompt_cache,
        prompt_cache_triage=args.prompt_cache_triage,
        prompt_cache_retrieval=args.prompt_cache_retrieval,
        # In the digest, so a ceiling run and a blind one over the same scan can
        # never collide on a name. The oracle prompt versions ride with it: they
        # are prompts, so two ceiling runs at different wordings are different
        # experiments in exactly the way two triage prompts are.
        ceiling=args.oracle,
        oracle_prompts=(
            ",".join(oracle_mod.instruction(st).name
                     for st in ("screening", "synthesis"))
            if args.oracle else ""
        ),
    ))
    with ui.timed_phase("Join — alerts onto route templates"), \
            metrics.stage("join") as stage:
        bundles = join.build_bundles(run)
        findings = join.build_findings(bundles)
        stage.counters["endpoints"] = len(bundles)
        stage.counters["findings"] = len(findings)
        ui.found(f"{sum(len(b.groups) for b in bundles)} alert groups → "
                 f"{len(findings)} findings across {len(bundles)} endpoints")
        ui.found(f"{sum(1 for b in bundles if b.has_static_context)} endpoints "
                 "carry Noir static context")

    # The deterministic arm runs inside build_findings, so its work is invisible
    # unless it is reported here: the control arm is half the experiment and was
    # only ever visible in the final summary.
    flagged = [f for f in findings if (f.get("deterministic") or {}).get("needs_rescan")]
    by_tool: dict[str, int] = {}
    by_rule: dict[str, int] = {}
    for f in flagged:
        by_tool[str((f["deterministic"] or {}).get("tool"))] = by_tool.get(
            str((f["deterministic"] or {}).get("tool")), 0) + 1
        rule = str((f.get("alert") or {}).get("plugin_id"))
        by_rule[rule] = by_rule.get(rule, 0) + 1
    arm = ui.open_phase("Arm 1 — deterministic rescan table")
    ui.item("flagged for rescan", f"{len(flagged)} of {len(findings)} findings")
    ui.item("by tool", by_tool or "-")
    # `None` in that mapping is the table asking for a rescan it cannot route:
    # the rule is not enumerated, so it escalated on risk alone and named no
    # tool. Verification will record `not-attempted`, which reads like a budget
    # decision. Named here, at the arm that produces it, because rule 40026 was
    # one of these and it was the corpus's only true positive.
    unroutable = by_tool.get("None", 0)
    if unroutable:
        rules = sorted({str((f.get("alert") or {}).get("plugin_id"))
                        for f in flagged
                        if not (f["deterministic"] or {}).get("tool")})
        ui.warn(
            f"{unroutable} of {len(flagged)} flagged finding(s) name NO TOOL, so "
            "nothing can verify them — rule(s) "
            + ", ".join(rules[:12])
            + (f", … ({len(rules)} in total)" if len(rules) > 12 else "")
            + ". Each is missing from the rescan table and escalated on risk "
              "alone. Adding a row (or a considered NEVER) is what turns these "
              "into a decision instead of a silent gap."
        )
    ui.item("by rule", dict(sorted(by_rule.items(), key=lambda kv: -kv[1])[:6]) or "-")
    ui.item("table", f"v{join.rescan_table.RESCAN_TABLE_VERSION}, "
                     f"{len(join.rescan_table.RULES)} rules, no model")
    arm.close()

    # Refused before anything is written or sent, dry run included: a run whose
    # code context grounds none of its endpoints would report a level it never
    # had. Judged on exactly the candidates the live arm would send.
    if args.use_llm:
        config.warn_if_unbounded(args)
        gate_candidates, _pruned = pass1_candidates(
            bundles, args.max_endpoints, args.prune_noninteractive_php)
        if assembler is not None:
            assembler.prepare(gate_candidates)
        gate_plan = plan_pass1(
            gate_candidates, findings, args.max_unmatched_findings,
            assembler.has_source if assembler is not None else None)
        try:
            require_located_handlers(
                assembler, [bundle for bundle, _pairs in gate_plan.work])
        except CodeContextUngrounded as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            return 2

    if args.dry_run:
        dry_run(
            bundles, findings, args.data_dir, run.timestamp,
            join.summarise(bundles, findings, [], run.zap_report.get("alerts", [])),
            pass1_context=args.peer_context,
            assembler=assembler,
            synthesis_calls=(
                max(1, args.synthesis_repeats)
                * max(1, len(_model_list(args.synthesis_models)) or 1)
                if args.use_synthesis else 0
            ),
            oracle_target=scan_target if args.oracle else None,
            prune_noninteractive_php=args.prune_noninteractive_php,
            max_alerts_per_call=args.max_alerts_per_call,
            max_unmatched_findings=args.max_unmatched_findings,
        )
        return 0

    with metrics.guard(args.data_dir):
        correlated: list[dict[str, Any]] = []
        llm_metadata: dict[str, Any] | None = None
        synthesis_metadata: dict[str, Any] | None = None
        if args.use_llm:
            try:
                with ui.timed_phase("Arm 2, pass 1 — per-endpoint LLM triage"), \
                        metrics.stage("llm_screening") as stage:
                    llm_metadata = run_llm_arm(
                        bundles, findings, screening_model, args.max_endpoints,
                        concurrency=args.concurrency,
                        pass1_context=args.peer_context,
                        prompt=screening_prompt,
                        stage_max_cost_usd=args.stage_max_cost,
                        run_max_cost_usd=args.run_max_cost,
                        prior_cost_usd=spent_before,
                        max_unmatched_findings=args.max_unmatched_findings,
                        max_minutes=args.screening_max_minutes,
                        assembler=assembler,
                        retrieval_mode=args.retrieval,
                        max_retrievals=args.retrieval_max_calls,
                        messages_path=run_paths.RunLayout(
                            args.data_dir, run.timestamp).path(run_paths.ZAP_MESSAGES),
                        source_dir=targets.target_source(scan_target),
                        oracle=oracle_mod.block(scan_target, "screening") if args.oracle
                        else None,
                        provider=triage_provider,
                        prune_noninteractive_php=args.prune_noninteractive_php,
                        max_alerts_per_call=args.max_alerts_per_call,
                    )
                    stage.counters.update(llm_metadata["usage"])
                    if llm_metadata.get("pruned_noninteractive_php"):
                        stage.counters["pruned_noninteractive_php"] = (
                            llm_metadata["pruned_noninteractive_php"])
                    # Retrievals sit beside the model calls, in the stage that made
                    # them: "what did pull cost" is a question about this stage's
                    # wall time and tokens, and a number kept only in the artifact
                    # would not join to either.
                    pulled = llm_metadata.get("retrieval") or {}
                    if pulled.get("calls"):
                        stage.counters["retrievals"] = pulled["calls"]
                        stage.counters["retrieval_bytes"] = pulled["bytes_returned"]
                        stage.counters["retrievals_failed"] = pulled["failed_calls"]
                # After pass 1 on purpose: pass 2 consumes its verdicts and needs
                # the finished finding list to cite ids from.
                if args.use_synthesis:
                    with ui.timed_phase("Arm 2, pass 2 — cross-endpoint synthesis"), \
                            metrics.stage("llm_synthesis") as stage:
                        correlated, synthesis_metadata = run_synthesis_arm(
                            bundles, findings,
                            join.summarise(
                                bundles, findings, [], run.zap_report.get("alerts", [])
                            ),
                            synthesis_model,
                            prompt=synthesis_prompt,
                            repeats=max(1, args.synthesis_repeats),
                            concurrency=args.concurrency,
                            timeout=args.synthesis_timeout_seconds,
                            max_prompt_tokens=args.synthesis_max_prompt_tokens,
                            models=_synthesis_members,
                            oracle=(oracle_mod.block(scan_target, "synthesis")
                                    if args.oracle else None),
                            provider=synthesis_provider,
                            providers=synthesis_providers,
                        )
                        stage.counters.update(synthesis_metadata["usage"])
            except LlmError as exc:
                print(f"ERROR: {exc}", file=sys.stderr)
                return 1

        artifact = join.build_artifact(
            run, bundles, findings, correlated, llm_metadata, synthesis_metadata,
            assembler.as_dict() if assembler is not None else None,
        )
        # Never inferred from a config field a reader has to know to look for: a
        # ceiling artifact says so at its top level, in a field whose name is the
        # warning. See `dast_orchestrator.analysis.oracle`.
        artifact["oracle_guided"] = bool(args.oracle)
        out_path = run_paths.RunLayout(args.data_dir, run.timestamp).ensure().path(
            run_paths.TRIAGE, args.out_suffix
        )

        # A model-comparison run must not silently replace the baseline it is meant
        # to be compared against. Same failure mode as the --no-llm guard below,
        # and the same remedy: refuse, and say which flag resolves it.
        previous_model = _existing_model(out_path)
        if (
            previous_model
            and llm_metadata
            and previous_model != llm_metadata.get("model")
            and not args.force
        ):
            print(
                f"ERROR: {out_path.name} holds results from {previous_model}, and this\n"
                f"       run used {llm_metadata.get('model')}. Overwriting would destroy the\n"
                "       baseline this run is meant to be compared against.\n"
                "       Re-run with --out-suffix <name> to keep both, or --force to replace.",
                file=sys.stderr,
            )
            return 1
        if not args.force and _would_discard_llm_results(out_path, artifact):
            print(
                f"ERROR: {out_path} already holds LLM results and this run has none.\n"
                "       Overwriting would throw away paid model output that cannot be\n"
                "       recovered without re-running the arm. Re-run with --force if that\n"
                "       is what you want, or keep the existing file and drop --no-llm.",
                file=sys.stderr,
            )
            return 1
        out_path.write_text(json.dumps(artifact, indent=2))

        summary = artifact["summary"]
        usage = (llm_metadata or {}).get("usage", {})
        synth_usage = (synthesis_metadata or {}).get("usage", {})
        # Only when the arm actually ran: a --no-llm run that named a model would
        # be recording a fact about a call it never made.
        if llm_metadata:
            metrics.record_tool(
                "openrouter",
                model=llm_metadata.get("model"),
                prompt_version=llm_metadata.get("prompt_version"),
                synthesis_prompt_version=(synthesis_metadata or {}).get("prompt_version"),
            )
        # Code-context source-resolution OUTCOME. `config` records only the asked
        # level (e.g. handler+trace); this records what that level PRODUCED — how
        # many candidate endpoints ctags resolved to handler source vs not. `None`
        # when code context is off, so a measured zero (a scope/path miss, as on
        # grafana and wordpress) never looks like "not asked". Full per-endpoint
        # detail stays in the triage artifact's evidence block.
        code_ctx = assembler.as_dict() if assembler is not None else {}
        metrics.record_results(
            findings=summary["findings"],
            raw_alerts=summary["raw_alerts"],
            deterministic_rescans=summary["deterministic_rescans"],
            llm_rescans=summary["llm_rescans"],
            llm_findings_asked=summary["llm_findings_asked"],
            llm_findings_unanswered=summary["llm_findings_unanswered"],
            correlated_findings=summary["correlated_synthesis_findings"],
            agreement=summary["agreement"],
            # Candidate endpoints ctags resolved to handler source vs not — the
            # outcome behind the asked `code_context` level. Mirrors the artifact's
            # evidence.endpoints_with_source so a run index / harness table can
            # carry it as a scalar. `None` when code context is off.
            code_context_endpoints_with_source=code_ctx.get("endpoints_with_source"),
            code_context_endpoints_without_source=code_ctx.get("endpoints_without_source"),
            # Of those, how many carry the endpoint's OWN handler, and by which
            # tier — "with source" also counts a whole file or a registration site.
            code_context_endpoints_handler_located=code_ctx.get("endpoints_handler_located"),
            code_context_endpoints_by_resolution=code_ctx.get("endpoints_by_resolution"),
            # The A/B number for --peer-context: a scalar the run index and the
            # harness table can carry, next to the full breakdown in the artifact.
            self_contradictions=(
                summary["llm_self_consistency"]["shared_handler_contradictions"]
            ),
            self_comparisons=(
                summary["llm_self_consistency"]["shared_handler_comparisons"]
            ),
            # Both passes' spend, summed, so "what does the AI layer cost per CI
            # run" is one number rather than an addition the reader has to perform.
            cost_usd=round(
                float(usage.get("cost_usd", 0.0)) + float(synth_usage.get("cost_usd", 0.0)), 6
            ),
            prompt_tokens=usage.get("prompt_tokens", 0) + synth_usage.get("prompt_tokens", 0),
            # What the provider served from its own cache. Recorded for BOTH passes
            # because they cache for opposite reasons and the numbers mean different
            # things: pass 1 is many small calls that share only a system prompt, so
            # it caches almost nothing; pass 2 sends the SAME whole-corpus prompt
            # `TRIAGE_SYNTHESIS_REPEATS` times, so everything after the first is nearly
            # free. Without marking it the repeats look as expensive as they naively
            # appear, and the pull-vs-push A/B — whose first question is whether caching
            # closes the gap — has no evidence either way.
            cached_prompt_tokens=(usage.get("cached_prompt_tokens", 0)
                                  + synth_usage.get("cached_prompt_tokens", 0)),
            completion_tokens=(
                usage.get("completion_tokens", 0) + synth_usage.get("completion_tokens", 0)
            ),
            model_calls=usage.get("calls", 0) + synth_usage.get("calls", 0),
            artifact=out_path.name,
        )
    # `guard` wrote the record leaving the block above (with an abort object had
    # the stage crashed — including after paid LLM calls). Clean path only here.
    print_summary(artifact)
    metrics.print_summary(files=[out_path.name, metrics.filename])
    return 0


__all__ = [
    'print_summary',
    'print_model_usage',
    'dry_run',
    'build_parser',
    'main',
]
