"""``dast verify`` — argparse plus orchestration for the verify stage.

Reads a finished ``triage.json`` off disk, resolves the run and config, drives
:func:`~dast_orchestrator.stages.verify.records.verify_all` over the selected
findings, and writes the artifact. The thin CLI entry; the judgement lives in
``records`` / ``probes``. Depends on every other verify submodule.
"""
from __future__ import annotations
import argparse
import json
import os
import re
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any
import anyio
import anyio.to_thread
from dast_orchestrator.foundation import config
from dast_orchestrator.adapters import auth
from dast_orchestrator.analysis import join
from dast_orchestrator.domain import rescan_table
from dast_orchestrator.foundation import redaction
from dast_orchestrator.foundation import run_lock
from dast_orchestrator.foundation import run_paths
from dast_orchestrator.foundation import schema
from dast_orchestrator.adapters import targets
from dast_orchestrator.foundation import ui
from dast_orchestrator.domain import verification
from dast_orchestrator.analysis import oracle as oracle_mod
from dast_orchestrator.analysis import verify_loop
from dast_orchestrator.adapters import retrieval as retrieval_mod
from dast_orchestrator.foundation import prompts as prompts_mod
from dast_orchestrator.foundation import metrics as run_metrics
from dast_orchestrator.analysis.join import JoinError
from dast_orchestrator.analysis import screening
from dast_orchestrator.analysis.screening import (
    LlmError,
    OpenRouterCorrelator,
    api_key_from_env,
)
from dast_orchestrator.domain.verification import (
    CONFIRMED,
    DispatchBudget,
    INCONCLUSIVE,
    NOT_ATTEMPTED,
    REFUTED,
)
from .common import *
from .probes import *
from .records import *
from dast_orchestrator.stages.verify import records

def dry_run(dispatchable: list[dict[str, Any]],
            correlated_plans: list[tuple[dict[str, Any], dict[str, Any] | None]],
            findings_by_endpoint: dict[Any, list[dict[str, Any]]],
            budget: DispatchBudget,
            fillers: dict[str, str] | None = None,
            auth_ctx: dict[str, str] | None = None,
            cfg: dict[str, Any] | None = None,
            contexts: "dict[str, dict[str, Any]] | None" = None,
            system_prompt: "str | None" = None,
            findings_by_id: "dict[str, dict[str, Any]] | None" = None,
            target: "targets.Target | None" = None,
            max_siblings: int = DEFAULT_MAX_SIBLINGS,
            oracle: "dict[str, Any] | None" = None) -> None:
    """The plan, and — when the loop would run — the exact round-1 prompt.

    One dry run rather than the two the old design needed (a plan-only one and a
    live-pass-1-then-dump-prompts one). Nothing is dispatched and nothing is
    sent, because a round-2 prompt cannot exist without a round-1 tool result:
    what can honestly be shown ahead of a run is the plan and the opening
    conversation, so that is what is shown.
    """
    cfg = cfg or loop_config()
    contexts = contexts or {}
    verified_routes = {
        str(f.get("endpoint_key") or f"{f.get('method')} {f.get('path')}")
        for f in dispatchable
    }
    print(f"Dispatch plan (budget: {budget.as_dict()}, configuration: {cfg}"
          + (", authenticated" if auth_ctx and auth_ctx.get("cookie") else "") + "):\n")
    per_tool: dict[str, int] = {}
    for finding in dispatchable:
        plan = build_dispatch(finding, findings_by_endpoint, fillers, auth_ctx)
        alert = finding.get("alert") or {}
        if plan is None or plan.get("tool") is None:
            print(f"  SKIP  {finding['finding_id']} {alert.get('name', '')[:40]} "
                  f"({_refusal_detail((plan or {}).get('refusal'))})")
            continue
        per_tool[plan["tool"]] = per_tool.get(plan["tool"], 0) + 1
        print(f"  {plan['tool']:7s} {finding['finding_id']} "
              f"{alert.get('plugin_id',''):>6} p={plan['arguments'].get('param','')!r} "
              f"{plan['arguments']['target'][:70]}")
    print("\n  correlated:")
    for correlated, plan in correlated_plans:
        if plan is None:
            print(f"  SKIP  {correlated['finding_id']} [{correlated.get('pattern')}] "
                  f"tool={correlated.get('suggested_tool')}")
            continue
        per_tool[plan["tool"]] = per_tool.get(plan["tool"], 0) + 1
        print(f"  {plan['tool']:7s} {correlated['finding_id']} "
              f"[{correlated.get('pattern')}] via {plan.get('via_finding_id')}")
        # The routes the claim predicts, which the line above never touches.
        for probe in build_sibling_dispatches(
                correlated, plan,
                (findings_by_id or {}).get(str(plan.get("via_finding_id") or "")),
                target, verified_routes, max_siblings, auth_ctx):
            per_tool[probe["tool"]] = per_tool.get(probe["tool"], 0) + 1
            print(f"  {probe['tool']:7s}   ↳ sibling {probe['route']} "
                  f"({probe['url_source']}) {probe['arguments']['target'][:70]}")
    print(f"\n  {sum(per_tool.values())} dispatches: {per_tool}. Nothing was run.")

    if cfg["invocation"] != "llm" or not dispatchable:
        return
    example = dispatchable[0]
    plan = build_dispatch(example, findings_by_endpoint, fillers, auth_ctx)
    context = verify_loop.build_context(
        example, contexts.get(example["finding_id"], {}).get("exchange"),
        contexts.get(example["finding_id"], {}).get("source"),
        fixed_tool=(plan or {}).get("tool"),
        max_rounds=cfg["max_rounds"], oracle=oracle,
        earlier_triage=verify_loop.triage_view(example))
    messages = verify_loop.build_messages(context, system_prompt)
    print(f"\n  Round-1 prompt for {example['finding_id']} "
          f"({sum(len(m['content']) for m in messages)} chars), verbatim:\n")
    for message in messages:
        print(f"  --- {message['role']} ---")
        print("\n".join("  " + line for line in message["content"].splitlines()))
    print("\n  Nothing was sent to any model.")


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
    config.add_env_flags(pre, "verify")
    # The user-facing package docstring, not this driver's developer docstring —
    # the SAME source `dast commands` renders, so --help and COMMANDS.md agree.
    from dast_orchestrator.stages import verify as _pkg
    parser = argparse.ArgumentParser(
        description=config.command_description(_pkg.__doc__), parents=[pre])
    parser.add_argument("run", metavar="<run_id>",
                        help=run_paths.RUN_ARG_HELP.format(
                            verb="verify",
                            default="the newest run with a triage"))
    parser.add_argument("--data-dir", type=Path, default=DATA_DIR)
    parser.add_argument("--out-suffix", dest="out_suffix", default="",
                        help="Suffix the OUTPUT artifact: "
                             "verification-<ts>-<suffix>.json.\n"
                             "--in-suffix picks the input variant and defaults "
                             "to this; shared with triage/report.")
    parser.add_argument(
        "--invocation", choices=verification.INVOCATIONS,
        default=config.default_for("VERIFY_INVOCATION"),
        help="HOW the tool is called, and when to stop asking. `llm` runs the "
             "round loop: every verdict-moving fix in this project's history was "
             "about invocation, never tool choice (which is always the "
             "deterministic lookup). `deterministic` is the fixed single-shot "
             "probe — the FULLY-DETERMINISTIC configuration, no key, no spend, "
             "the control every LLM configuration is measured against.")
    parser.add_argument(
        "--max-rounds", type=int, default=int(config.default_for("VERIFY_MAX_ROUNDS")),
        help="Rounds one loop may run before it must conclude (propose, react, "
             "refine). With the per-run cost ceiling this bounds the loop's "
             "spend — a runaway loop is a mistake to make impossible.\n"
             "Ignored under --invocation deterministic, which is single-shot by "
             "nature.")
    parser.add_argument(
        "--retrieval",
        choices=retrieval_mod.RETRIEVAL_MODES,
        default=config.default_for("VERIFY_RETRIEVAL"),
        help="How the loop gets the handler source. `push` (default) attaches "
             "what `build_context` pre-resolved; `pull` also lets the model ask "
             "the read-only context server for more, mid-loop, the same arm "
             "triage's pull path uses. `pull` is bounded by "
             "--retrieval-max-calls and only applies under --invocation llm.")
    parser.add_argument(
        "--retrieval-max-calls", type=int, dest="retrieval_max_calls",
        default=int(config.default_for("VERIFY_RETRIEVAL_MAX_CALLS")),
        help="Retrievals one finding's loop may make before the tools are "
             "withdrawn and the model must conclude with what it has. Only "
             "meaningful with --retrieval pull.")
    parser.add_argument(
        "--in-suffix", dest="in_suffix", default=None, help="Which triage variant to verify (triage-<SUFFIX>.json); "
             "an empty string picks the base triage.json. The case for it "
             "is verifying ONE stored triage several times under different "
             "settings — the outputs must differ in name while the input must "
             "not.\n"
             "Falls back to --out-suffix, which is what a `triage verify` "
             "sequence wants (there the same suffix names both).")
    parser.add_argument("--dry-run", action="store_true",
                        default=config.env_bool("VERIFY_DRY_RUN"),
                        help="Print the dispatch plan and the round-1 prompts "
                        "and stop, running no tool and sending nothing. Spends "
                        "nothing and needs no key.\n"
                        "Set it via the env only deliberately — it turns a real "
                        "run into a no-op.")
    # The dispatch budget: flags first, env as the default, dataclass as the
    # floor — the same precedence every other knob in the pipeline uses.
    parser.add_argument(
        "--max-dispatch-all-rules", type=int, help="Dispatch cap for every ZAP rule that --max-dispatch-rule does not "
             "name; -1 disables it. Without a ceiling here one noisy passive "
             "rule owns the whole verification budget \u2014 rule 10031 alone "
             "supplies most flags on Gitea. This layer decides COVERAGE: it "
             "drops findings, it never shortens the ones it keeps.\n"
             "Overridden per rule by --max-dispatch-rule; bounded by "
             "--max-dispatches-total.",
    )
    parser.add_argument(
        "--max-dispatch-rule", action="append", default=[], metavar="<id>=<n>",
        help="Dispatch cap for ONE ZAP rule, as ID=N (e.g. 40018=40); -1 "
             "disables the cap for that rule, 0 never dispatches it. Several "
             "assignments may be comma-separated in one argument or given as "
             "repeated flags. On a noisy target most budget refusals are the "
             "per-rule cap, and a single blanket number could not let one rule "
             "run further without moving every other with it.\n"
             "Overrides --max-dispatch-all-rules for the named rule; never "
             "outlives --max-dispatches-total, which ends the run whatever a "
             "rule was still allowed.",
    )
    parser.add_argument(
        "--max-dispatches-total", type=int, help="Cap tool invocations for the WHOLE RUN; -1 disables it. "
             "Cross-endpoint, not per endpoint: one number for the stage, which "
             "is what `_total` says.\n"
             "The outer bound over --max-dispatch-all-rules and "
             "--max-dispatch-rule; reaching it ends the run.",
    )
    parser.add_argument(
        "--max-minutes", type=int, help="Wall-clock cap for the dispatch stage; -1 disables it. Disabled "
             "together with the count caps it is an EXHAUSTIVE run — every "
             "selected finding dispatched, nothing left not-attempted for a "
             "budget reason.\n"
             "An exhaustive run is then bounded only by --tool-timeout per "
             "invocation, so size it before starting one.",
    )
    parser.add_argument(
        "--tool-timeout", type=int, help="Hard timeout for one tool invocation; a kill is recorded "
             "inconclusive, never refuted.\n"
             "The per-invocation bound that backstops an exhaustive "
             "--max-minutes -1 run.",
    )
    parser.add_argument(
        "--prompt-cache-verify", dest="prompt_cache_verify", action="store_true",
        default=config.default_for("VERIFY_PROMPT_CACHE").strip().lower()
        not in ("0", "false", "no", "off"),
        help="Mark the verification loop's stable prefix as cacheable. Each "
             "round re-sends the system prompt, the finding, the handler source "
             "and every prior round's output, so most of its prompt tokens are a "
             "cacheable stable prefix.\n"
             "--prompt-cache is the master switch for all multi-turn caching; "
             "--no-prompt-cache-verify is this site's off form.",
    )
    parser.add_argument(
        "--no-prompt-cache-verify", dest="prompt_cache_verify",
        action="store_false", help="Off form of --prompt-cache-verify.",
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
        "--oracle", action="store_true",
        default=config.env_bool("SHARED_ORACLE"),
        help="Oracle-guided mode: hand every LLM stage the target's documented "
             "vulnerabilities (targets/<name>/oracle.md) and measure how much "
             "it still confirms. An upper bound on what this architecture could "
             "detect WITH perfect prior knowledge — never a detection rate, "
             "never in the same table as a blind run.\n"
             "Shared with triage so the whole chain runs guided or blind, "
             "never half; the gap to a blind run sizes the 'detectable but "
             "missed' set.",
    )
    parser.add_argument(
        "--oracle-seed-dispatch", dest="oracle_seed_dispatch",
        action="store_true",
        default=config.env_bool("VERIFY_ORACLE_SEED_DISPATCH"),
        help="Oracle-seeded verify dispatch (needs --oracle). For every "
             "ground-truth marker whose documented sink raised no ZAP finding, "
             "synthesise a dispatch FROM THE MARKER — the sink URL, the tool the "
             "rescan table routes the marker's rule to, and the marker's auth — "
             "so a CVE whose in-band ZAP reach is budget-bound (Cacti's "
             "CVE-2022-46169 at the authenticated ceiling) is still confirmed "
             "out of band. A LABELED ADDITIONAL configuration: the verdict still "
             "resolves through resolve_verdict and the record is marked "
             "oracle-seeded, never counted with blind detections.\n"
             "Off by default and ignored without --oracle, so it can never touch "
             "a blind run and the baseline's artifacts are byte-identical.",
    )
    parser.add_argument(
        "--max-siblings", type=int, default=int(config.default_for("VERIFY_MAX_SIBLINGS")),
        help="Turn ON the propagation dispatch and cap it at N unflagged "
             f"sibling routes per claim; 0 is off, {SIBLINGS_WHEN_ENABLED} the "
             "sensible value when on. These are routes a cross-endpoint claim "
             "PREDICTS share a weakness and the scan never flagged; a "
             "confirmation on one is a finding no part of the deterministic "
             "pipeline could reach.\n"
             "Off by default: it changes what a run contains (extra dispatches, "
             "a new finding class, a target reached over dast-net), so a run "
             "with it is not comparable to one without, and it is so far "
             "unvalidated — two live runs, zero confirmations.",
    )
    parser.add_argument(
        "--interactsh-server", default=config.default_for("VERIFY_INTERACTSH_SERVER"),
        help="Self-hosted interactsh sink for out-of-band confirmation. Never "
             "the public oast.pro pool — it would send this target's "
             "out-of-band interactions to someone else's server.\n"
             "Used only when --oob is on.",
    )
    parser.add_argument(
        "--nuclei-templates-volume",
        default=config.default_for("VERIFY_NUCLEI_TEMPLATES_VOLUME"), help="Named Docker volume holding the pinned nuclei templates; the "
             "image ships none.\n"
             "Populate it once with -update-templates, then it runs offline.",
    )
    parser.add_argument(
        "--oob", action="store_true",
        default=config.env_bool("VERIFY_OOB"),
        help="Arm out-of-band (OAST) nuclei templates against the self-hosted "
             "interactsh sink. On Gitea it changed no verdict and roughly tripled "
             "the stage's wall time, its only OOB item needing git operations DAST "
             "cannot reach; turn it on for a target "
             "with reachable SSRF or blind-injection surface.\n"
             "Needs --interactsh-server; --no-oob is the off form.",
    )
    parser.add_argument(
        "--no-oob", dest="oob", action="store_false",
        help="Force out-of-band templates off, the off form of --oob.\n"
             "Overrides VERIFY_OOB=on from an env file or a harness sheet "
             "without editing it.",
    )
    parser.add_argument(
        "--model", default=config.default_for("VERIFY_MODEL"),
        help="The ONE model the whole loop uses — every round's invocation "
             "proposal and its final category. Always a dated/immutable "
             "snapshot, never a floating alias: a re-run whose weights moved is "
             "not a reproduction.\n"
             "Has its own pinned default and does NOT inherit the triage model: "
             "a stage's model is set per stage, never bled in from another.\n"
             "Unused under --invocation deterministic, which calls no model.",
    )
    parser.add_argument(
        "--provider", default=config.default_for("VERIFY_PROVIDER"), help="Hard-pin the OpenRouter provider (a slug, or a comma list) for the "
             "verify model — the sibling of --model (VERIFY_MODEL/VERIFY_PROVIDER). "
             "A pinned model routes to exactly those providers with fallbacks "
             "off (fully reproducible); empty (the default) uses the throughput/"
             "require-parameters preference.",
    )
    parser.add_argument(
        "--verify-prompt", dest="verify_prompt",
        default=config.default_for("VERIFY_PROMPT_VERSION"), help="Which prompts/verify/verify.v<N>.md the loop sends. Pinned the same way "
             "as the triage prompts, so a harness row can A/B the wording.\n"
             "Falls back to the newest version on disk.",
    )
    parser.add_argument(
        "--auth", choices=("none", "user", "admin"),
        default=config.default_for("SHARED_AUTH_MODE"),
        help="Verify as the target's seeded 'user' or 'admin' account, or "
             "'none' for anonymous. The session cookie is threaded into every "
             "tool probe, so guarded routes that make pass-1 findings "
             "inconclusive (needs_auth) can actually be settled.\n"
             "Needs no OpenRouter key; match it to the scan's --auth.",
    )
    parser.add_argument(
        "--force", action="store_true",
        help="Run even though another process holds this stage's lock on the "
             "run directory. Overrides the refusal; it does not coordinate the "
             "two runs.",
    )
    config.add_targets_dir_flag(parser)
    config.normalize_metavars(parser)
    return parser


@run_lock.guarded
def main(argv: "list[str] | None" = None) -> int:
    pre = argparse.ArgumentParser(add_help=False)
    config.add_env_flags(pre, "verify")
    known, _ = pre.parse_known_args(argv)
    # Loaded before the parser is built, so every ``os.getenv`` default below
    # sees the stage's file and an explicit flag still wins (see config.py).
    env = config.load_stage_env("verify", known.env_file)

    parser = build_parser()
    args = parser.parse_args(argv)
    overridden = config.apply_explicit_overrides(env, args, parser, argv)
    # The wrappers are separate processes that read these from the environment;
    # a flag has to reach them the same way.
    for value, var in ((args.interactsh_server, "VERIFY_INTERACTSH_SERVER"),
                       (args.nuclei_templates_volume, "VERIFY_NUCLEI_TEMPLATES_VOLUME")):
        if value:
            os.environ[var] = str(value)
    # `caching_enabled()` reads the environment, so the flag has to reach it the
    # same way the wrappers' settings do.
    os.environ["SHARED_PROMPT_CACHE"] = "1" if args.prompt_cache else "0"
    os.environ["VERIFY_PROMPT_CACHE"] = "1" if args.prompt_cache_verify else "0"
    if overridden:
        ui.warn(f"{ui.short_path(known.env_file)} supplies (no flag given): "
                f"{', '.join(sorted(overridden))}")

    # Point target discovery and source resolution at the configured dir before
    # the target is looked up by URL below.
    targets.use_dir(args.targets_dir)

    try:
        # The input variant and the output name are separate settings. They
        # coincide in a `triage verify` sequence, which is why one flag did
        # both for a while — but that made it impossible to verify a single
        # stored triage under several configurations, i.e. exactly the
        # comparison the harness exists to run.
        in_suffix = args.out_suffix if args.in_suffix is None else args.in_suffix
        layout, source = _find_correlation(
            args.data_dir, args.run, in_suffix
        )
    except JoinError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    # Claimed on the *output* suffix, not the input one: two verifications of
    # one correlation under different names write different files and may run
    # together, while two writing `verification-hybrid.json` may not. Released
    # by `@run_lock.guarded` however this returns.
    run_lock.claim(layout.dir, "verify", args.out_suffix, force=args.force)

    artifact_in = json.loads(source.read_text())
    try:
        schema.check(source.name, artifact_in, source)   # §R5: fail on a bad triage now
    except schema.ArtifactError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    findings = artifact_in.get("findings", [])
    correlated_findings = artifact_in.get("correlated_findings", [])
    run_id = layout.run_id

    findings_by_id = {f["finding_id"]: f for f in findings}
    findings_by_endpoint: dict[Any, list[dict[str, Any]]] = {}
    for f in findings:
        key = f.get("endpoint_key") or (f.get("method"), f.get("path"))
        findings_by_endpoint.setdefault(key, []).append(f)

    try:
        rule_caps = verification.parse_rule_caps(args.max_dispatch_rule)
    except ValueError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    budget = DispatchBudget.from_env().override(
        max_dispatch_all_rules=args.max_dispatch_all_rules,
        rule_caps=tuple(sorted(rule_caps.items())),
        max_dispatches_total=args.max_dispatches_total,
        max_minutes=args.max_minutes,
        tool_timeout_seconds=args.tool_timeout,
    )
    # The budget is assembled from flag, env and defaults, so the check has to
    # see the resolved numbers rather than the parsed flags.
    config.warn_if_unbounded(args, {
        "max_dispatch_all_rules": budget.max_dispatch_all_rules,
        "max_dispatches_total": budget.max_dispatches_total,
        "max_minutes": budget.max_minutes,
        "tool_timeout": budget.tool_timeout_seconds,
    })
    dispatchable = select_findings(findings)

    # Which target this scan hit decides the benign form fillers for POST bodies
    # and the login flow — resolved from the URL the correlation recorded, so no
    # target name has to be threaded through the artifacts.
    scan_url = (artifact_in.get("source") or {}).get("target", "")
    target = targets.for_url(scan_url)
    fillers = target.form_fillers

    # Probe context, so the verification tools get the same auth capabilities
    # ZAP has. CSRF handling for form POSTs is set whenever the target declares a
    # CSRF field — even unauthenticated — so a login-SQLi probe is not refuted
    # merely for lacking a token. The session cookie is added only under --auth.
    auth_ctx: dict[str, Any] = {}
    # Affirmative record that the probes ran logged IN (None on an unauthenticated
    # run), set from the confirmed session below. Written to the artifact so a
    # silently-logged-out authenticated corpus — the campaign failure — is visible.
    auth_authenticated: "bool | None" = None
    if target.auth:
        auth_ctx["session_cookie"] = target.auth.session_cookie
        if target.auth.csrf_field:
            auth_ctx["csrf_field"] = target.auth.csrf_field
            auth_ctx["csrf_url"] = f"{target.base_url.rstrip('/')}{target.auth.login_path}"
    # Fixed request headers the scan injected to reach a header-gated sink — not a
    # login, but the same "reach the target the way ZAP did" purpose as CSRF
    # handling above, so it belongs here even in an unauthenticated run.
    if target.scan_headers:
        auth_ctx["headers"] = "\n".join(
            f"{name}: {value}" for name, value in target.scan_headers.items()
        )
    if args.auth != "none":
        if target.auth is None:
            print(f"ERROR: target {target.name!r} defines no login flow; "
                  "cannot run --auth.", file=sys.stderr)
            return 1
        try:
            session = auth.login(target.base_url, target.auth, args.auth)
        except auth.AuthError as exc:
            print(f"ERROR: authentication failed: {exc}", file=sys.stderr)
            return 1
        auth_ctx["cookie"] = session.cookie_header()
        auth_authenticated = session.authenticated
        print(f"Verifying as {session.username!r} ({session.mode}); session "
              "confirmed authenticated, threaded into every probe.")
    # Oracle (ceiling) only: mark the sink ROUTES the markers call UNAUTHENTICATED,
    # so `_apply_auth` never forces the scan's session cookie onto their probes —
    # a valid session can route a poller-auth-bypass sink like Cacti's
    # remote_agent.php off its unauthenticated branch and suppress the CVE the
    # ceiling measures. Computed once, here, where the cookie is established, so
    # every probe builder (the table dispatch, the model-directed loop, correlated
    # and sibling probes) inherits it through auth_ctx. Sink ROUTES only — the
    # answer key never reaches the model, and a blind run never fills this, so the
    # loop's independence is untouched.
    # Oracle-seeded dispatch markers: the target's ground-truth markers, loaded
    # ONLY under --oracle + --oracle-seed-dispatch (else None, so the feature is
    # inert and a blind run never reaches it). Read here, where the marker set is
    # already loaded for the cookie rule above.
    oracle_seed_markers: "list[Any] | None" = None
    if args.oracle:
        from dast_orchestrator.stages import ground_truth as _gt  # noqa: PLC0415
        if _gt.has_markers(target.name):
            _markers = _gt.MarkerSet.load(target.name).markers
            auth_ctx["cookie_free_routes"] = frozenset(
                m.probe_route for m in _markers if m.auth == _gt.AUTH_NONE
            )
            if args.oracle_seed_dispatch:
                oracle_seed_markers = _markers
    auth_ctx = auth_ctx or None

    # Resolved before anything runs, so `--ceiling` against a target with no
    # oracle document fails immediately rather than after the tools have run —
    # a run that silently went blind would still be labelled a ceiling.
    # The transport for the sibling reachability pre-check. Built once, here,
    # so a run that dispatches no sibling probe never spawns a container — and
    # so the loop takes it as data rather than reaching for docker itself.
    # The pre-check must ask AS THE RUN ASKS. Probed anonymously under `--auth`
    # it recorded the status of a different request than the one filed beside
    # it: every served sibling route answered 302 (the redirect to the login
    # page), which is what an anonymous GET gets and says nothing about what the
    # authenticated probe then saw. `summary.siblings.by_route_status` is the
    # whole readout of §N4,
    # so an anonymous status there does not merely lose detail, it answers the
    # question wrongly.
    check_route = (route_checker(auth.container_fetch(
        cookie=(auth_ctx or {}).get("cookie", ""))
    ) if args.max_siblings > 0 else None)

    oracle_block: dict[str, Any] | None = None
    if args.oracle:
        try:
            oracle_mod.require(target)
        except oracle_mod.OracleError as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            return 2
        oracle_block = oracle_mod.block(target, "verify")

    correlated_plans = [
        (c, build_correlated_dispatch(c, findings_by_id, auth_ctx, args.oob))
        for c in correlated_findings
    ]

    cfg = loop_config(args.invocation, args.max_rounds)
    looping = cfg["invocation"] == "llm"

    mode = "hybrid" if looping else "deterministic"
    ui.headline(f"Verification · {mode}",
                f"run {run_id}  →  {source.parent}")
    plan = ui.open_phase("Dispatch plan")
    ui.item("correlation", source.name)

    # Model and prompt lead the plan (rows 2 and 3) — the prompt is loaded even
    # for a dry run so naming a version that is not on disk fails before anything
    # else happens, not after the tools have run.
    verify_prompt: "prompts_mod.Prompt | None" = None
    if looping:
        ui.item("model", args.model)
        try:
            verify_prompt = prompts_mod.load("verify", args.verify_prompt)
        except prompts_mod.PromptError as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            return 2
        ui.item("prompt", verify_prompt.path.name)

    ui.item("selected", f"{len(dispatchable)} flagged + "
                        f"{len(correlated_findings)} correlated")
    ui.item("configuration",
            f"invocation {cfg['invocation']}"
            + (f" · ≤{cfg['max_rounds']} rounds" if looping else " (single-shot)"))
    ui.item("out-of-band", "armed" if args.oob else "off")
    if oracle_block is not None:
        # Loud, and on every oracle run. The whole risk of this mode is that
        # its numbers are read as detection numbers by whoever opens the
        # artifact next; saying so once here and once in the artifact is the
        # cheapest guard there is.
        ui.warn(
            "ORACLE-GUIDED (--oracle): the loop is being told this target's "
            "documented vulnerabilities before it probes. What comes out is an "
            "upper bound on what this pipeline could confirm WITH prior "
            "knowledge — it is NOT a detection rate and must never share a "
            "table with a blind run."
        )

    # The budget, one row per ceiling actually in force; NO_CAP is "off" and is
    # not printed. Kept near the bottom so the finding counts read first.
    for label, value, suffix in (
        ("tool timeout", budget.tool_timeout_seconds, "s"),
        ("dispatch cap · rule", budget.max_dispatch_all_rules, ""),
        ("dispatch cap · run", budget.max_dispatches_total, ""),
        ("stage timeout", budget.max_minutes, " min"),
    ):
        if value != verification.NO_CAP:
            ui.item(label, f"{value}{suffix}")
    if budget.rule_caps:
        ui.item("per-rule caps",
                ", ".join(f"{rule}={cap}" for rule, cap in budget.rule_caps))

    # The cost ceiling closes the plan, mirroring triage. Only meaningful when a
    # model is in the loop — the deterministic arm spends nothing. Printed as what
    # this stage may actually spend, after what earlier stages of the run spent.
    spent_before = 0.0
    if looping:
        spent_before = run_metrics.run_cost_so_far(
            args.data_dir, run_id, args.out_suffix)
        limit = screening.headroom(args.stage_max_cost, args.run_max_cost,
                                   spent_before)
        if limit >= 0:
            ui.item("cost ceiling",
                    f"${limit:.4f}"
                    + (f" (${spent_before:.4f} already spent by this run)"
                       if spent_before else ""))
    plan.close(timed=False)

    # The handler source and the HTTP exchange the loop reasons from. Assembled
    # here, once, exactly as triage assembles them — and deliberately WITHOUT
    # triage's conclusions: see `verify_loop.build_context`.
    contexts: dict[str, dict[str, Any]] = {}
    if looping:
        contexts = build_contexts(layout, artifact_in, dispatchable, target)

    if args.dry_run:
        dry_run(dispatchable, correlated_plans, findings_by_endpoint, budget,
                fillers, auth_ctx, cfg, contexts,
                verify_prompt.text if verify_prompt else None,
                findings_by_id, target, args.max_siblings, oracle_block)
        return 0

    dispatch_phase = ui.open_phase("Dispatching")
    client: OpenRouterCorrelator | None = None
    retrieval_arm: "retrieval_mod.Retrieval | None" = None
    if looping:
        try:
            api_key_from_env()  # validated here so the failure is actionable
        except LlmError as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            dispatch_phase.close()
            return 1
        if args.retrieval == retrieval_mod.PULL_MODE:
            # Opened here, before the loop spends anything: a pull run whose
            # context server is broken must fail while nothing is paid for, not
            # finding by finding. The source is the same tree triage's pull
            # reads, and the exchange sidecar the scan wrote.
            try:
                retrieval_arm = retrieval_mod.Retrieval.open(
                    messages_path=layout.path(run_paths.ZAP_MESSAGES),
                    source_dir=targets.target_source(target),
                    max_calls=args.retrieval_max_calls,
                )
            except retrieval_mod.RetrievalError as exc:
                print(f"ERROR: {exc}", file=sys.stderr)
                dispatch_phase.close()
                return 1
            ui.item("retrieval",
                    f"pull (≤ {args.retrieval_max_calls}/finding)")
        client = OpenRouterCorrelator(
            model=args.model,
            stage_max_cost_usd=args.stage_max_cost,
            run_max_cost_usd=args.run_max_cost,
            prior_cost_usd=spent_before,
            provider=args.provider,
        )

    metrics = run_metrics.RunMetrics(run_id, kind="verify", label=args.out_suffix)
    metrics.record_config(verify_config(
        auth_mode=args.auth,
        oob=args.oob,
        tool_choice=cfg["tool_choice"],
        invocation=cfg["invocation"],
        retrieval=args.retrieval if looping else retrieval_mod.PUSH_MODE,
        retrieval_max_calls=(args.retrieval_max_calls
                             if args.retrieval == retrieval_mod.PULL_MODE else 0),
        max_rounds=cfg["max_rounds"],
        model=args.model if looping else "",
        # The provider PREFERENCE the loop was configured with (empty on the
        # deterministic arm, which calls no model) — recorded beside the model for
        # the same reason triage records its providers: it shapes cost and routing,
        # and the resolved config must say what was asked for.
        provider=args.provider if looping else "",
        # How many sibling routes a propagation claim may probe — a behaviour knob
        # that bounds the dispatch stage's work.
        max_siblings=args.max_siblings,
        verify_prompt_version=verify_prompt.version if verify_prompt else None,
        prompt_cache=args.prompt_cache,
        prompt_cache_verify=args.prompt_cache_verify,
        vocabulary_version=verification.VERIFICATION_VOCAB_VERSION,
        # In the digest, so a ceiling run and a blind one over the same
        # correlation can never collide on a name. The oracle prompt rides with
        # it — it is a prompt, and two ceiling runs at different wordings are
        # different experiments.
        ceiling=args.oracle,
        # Recorded only when on, so an off run's config block — and the digest
        # over it — are byte-identical to one produced before this feature.
        **({"oracle_seed_dispatch": True} if args.oracle_seed_dispatch else {}),
        oracle_prompt=(oracle_mod.instruction('verify').name if args.oracle else ""),
        max_cost_usd=args.stage_max_cost if args.stage_max_cost >= 0 else None,
        run_max_cost_usd=args.run_max_cost if args.run_max_cost >= 0 else None,
        **budget.as_dict(),
    ))
    with metrics.guard(args.data_dir):
        records._loop_prompt = verify_prompt
        try:
            with metrics.stage("dispatch") as stage:
                (verifications, correlated_out, siblings, per_rule, loop_info,
                 oracle_seeded) = anyio.run(
                    verify_all, dispatchable, correlated_plans, budget,
                    findings_by_endpoint, cfg, client, findings_by_id, fillers,
                    auth_ctx, args.oob, contexts,
                    verify_prompt.text if verify_prompt else None,
                    target, args.max_siblings, oracle_block, check_route,
                    retrieval_arm, oracle_seed_markers, args.auth,
                )
                stage.counters["dispatched"] = sum(
                    1 for r in verifications + correlated_out + siblings
                    if r.get("outcome") not in (
                        NOT_ATTEMPTED, verification.SIBLING_UNREACHABLE)
                )
                # Two numbers, because they are two facts: how many routes the
                # propagation claims named, and how many were worth a probe.
                stage.counters["sibling_routes"] = len(siblings)
                stage.counters["sibling_probes"] = sum(
                    1 for r in siblings if r.get("outcome") not in (
                        NOT_ATTEMPTED, verification.SIBLING_UNREACHABLE))
                stage.counters["rounds"] = loop_info["rounds_run"]
                stage.counters["tool_rounds"] = loop_info["tool_rounds"]
                # The full LLM accounting — the per-call log included — recorded into
                # the stage exactly as triage records its arms (`stage.counters.update`
                # of `usage.as_dict()`), so the §T3 per-call cost / latency / cache cuts
                # and the `dast costs` provider column cover verify too, not just
                # triage. Absent on the deterministic configuration, which calls no
                # model and so has no per-call log to write (a missing measurement,
                # never a measured zero).
                loop_usage = (loop_info.get("metadata") or {}).get("usage") or {}
                if loop_usage:
                    stage.counters.update(loop_usage)
                # Oracle-seeded marker probes, counted only when the dispatch ran
                # (VERIFY_ORACLE_SEED_DISPATCH) so an off run's metrics record is
                # byte-identical — a ceiling reading, kept its own counters so it
                # is never summed with the blind dispatch totals.
                if oracle_seeded:
                    stage.counters["oracle_seeded_probed"] = len(oracle_seeded)
                    stage.counters["oracle_seeded_confirmed"] = sum(
                        1 for r in oracle_seeded if r.get("outcome") == CONFIRMED)
        finally:
            if client is not None:
                client.close()
            dispatch_phase.close()

        artifact = build_artifact(
            source.name, run_id, budget, verifications, correlated_out, per_rule,
            loop_info, args.oob, siblings,
            table_version=(artifact_in.get("rescan_table") or {}).get("version"),
            oracle_seeded=oracle_seeded,
        )
        # Which account the probes ran as; three verify runs at different modes are
        # not comparable, so it rides in the artifact next to the outcomes.
        artifact["auth_mode"] = args.auth
        # Whether the session was CONFIRMED authenticated (None when unauthenticated).
        # `auth.login` is fail-closed, so a value of false never reaches here — the
        # field is the affirmative provenance, not a status that can be ignored.
        artifact["auth_authenticated"] = auth_authenticated
        # Never inferred from a config field a reader has to know to look for: a
        # ceiling artifact says so at its top level, in a field whose name is the
        # warning.
        artifact["oracle_guided"] = bool(args.oracle)
        out_path = layout.path(run_paths.VERIFICATION, args.out_suffix)
        # NFR-06: redact the session cookie (by header name) and the target's
        # seeded login passwords (which a tool like sqlmap replays into the
        # stored probe body) the moment the artifact is written.
        out_path.write_text(json.dumps(redaction.scrub(
            artifact,
            redaction.target_secrets(target),
            redaction.target_cookie_names(target),
        ), indent=2))

        for name, image in TOOL_IMAGES.items():
            metrics.record_tool(name, image=image,
                                digest=run_metrics.docker_image_digest(image))
        meta = loop_info.get("metadata") or {}
        usage = meta.get("usage") or {}
        if meta:
            metrics.record_tool("openrouter", model=meta.get("model"),
                                prompt_version=meta.get("prompt_version"))
        summary = artifact["summary"]
        metrics.record_results(
            selected=summary["selected"],
            correlated_selected=summary["correlated_selected"],
            dispatched=summary["dispatched"],
            confirmed=summary["by_outcome"].get(CONFIRMED, 0),
            refuted=summary["by_outcome"].get(REFUTED, 0),
            inconclusive=summary["by_outcome"].get(INCONCLUSIVE, 0),
            not_attempted=summary["by_outcome"].get(NOT_ATTEMPTED, 0),
            # The not-attempted breakdown by reason, so a budget-exhausted
            # dispatch (a valid-looking artifact with everything not-attempted)
            # is derivable as a limit from the metrics record alone — not only
            # from the per-finding `stopped_because` prose in verification.json.
            not_attempted_by_reason=summary.get("not_attempted_by_reason"),
            tool_seconds=summary["tool_seconds"],
            rounds_run=loop_info["rounds_run"],
            tool_rounds=loop_info["tool_rounds"],
            findings_looped=loop_info["findings_looped"],
            # The classification-audit disagreement rate, free on the model's own
            # tool calls: how often the wrapper's fixed rules and the model read the
            # SAME output differently. The number this redesign exists to produce.
            # `None`, not 0, when no record carried two readings: a deterministic
            # run has no disagreement rate, and a zero in that column would read as
            # one on a comparison sheet.
            verdicts_flagged=(loop_info["agreement"].get(verification.FLAGGED, 0)
                              if sum(loop_info["agreement"].values()) else None),
            signal_contradictions=(loop_info.get("signals") or {}).get("contradiction"),
            rounds_without_signal=(loop_info.get("signals") or {}).get("not_declared"),
            # `None`, not 0.0, when no model ran. The deterministic configuration
            # dispatches tools and calls no model, so there is no spend to measure —
            # and a missing measurement and a measured zero must never look alike.
            cost_usd=(round(float(usage.get("cost_usd", 0.0)), 6) if meta else None),
            prompt_tokens=(usage.get("prompt_tokens") if meta else None),
            completion_tokens=(usage.get("completion_tokens") if meta else None),
            # Whether the stable prefix each round re-sends was actually served from
            # the provider's cache. Zero means "no evidence of caching" — not
            # reported and not hit are indistinguishable from here — so it is a
            # measurement to read, never a conclusion.
            cached_prompt_tokens=(usage.get("cached_prompt_tokens") if meta else None),
            artifact=out_path.name,
        )
        # The oracle-seeded tally, recorded only when the dispatch ran so an off
        # run's results block is byte-identical — kept apart from the blind
        # confirmed/refuted counts above because it is a ceiling reading.
        if oracle_seeded:
            os_summary = summary.get("oracle_seeded") or {}
            metrics.record_results(
                oracle_seeded_probed=os_summary.get("markers_probed", 0),
                oracle_seeded_confirmed=(os_summary.get("by_outcome") or {}).get(
                    CONFIRMED, 0),
            )
    # `guard` wrote the record leaving the block above (with an abort object had
    # the stage crashed). Clean path only from here.
    print_summary(artifact)
    print_model_usage(loop_info)
    metrics.print_summary(files=[out_path.name, metrics.filename])
    return 0


def _find_correlation(data_dir: Path, run_id: str | None,
                      suffix: str = "") -> tuple[run_paths.RunLayout, Path]:
    """The run + correlation artifact to verify: a named run, or the newest on disk.

    ``"latest"`` is accepted and means the same as omitting the flag — the newest
    run carrying the correlation this command needs.

    ``suffix`` selects a model-comparison variant (``triage-<suffix>.json``);
    empty means the baseline ``triage.json``.
    """
    basename = run_paths._splice_suffix(run_paths.TRIAGE, suffix)
    if run_id and not run_paths.is_latest(run_id):
        try:
            layout = run_paths.RunLayout.resolve(data_dir, run_id)
        except ValueError as exc:
            raise JoinError(str(exc)) from exc
        path = layout.path(run_paths.TRIAGE, suffix)
        if not path.is_file():
            raise JoinError(f"no {basename} for run {run_id} in {data_dir}")
        return layout, path
    # Same rule as triage: "latest" is the newest run, not the newest one
    # that happens to be usable. Silently verifying an older run is how a stale
    # artifact gets overwritten while the run you just made is ignored.
    runs = run_paths.RunLayout.runs(data_dir)
    if not runs:
        raise JoinError(f"no runs in {data_dir}; run `scan` first")
    newest = run_paths.RunLayout(data_dir, runs[-1])
    if newest.has(run_paths.TRIAGE, suffix):
        return newest, newest.path(run_paths.TRIAGE, suffix)

    layout = run_paths.RunLayout.latest_with(data_dir, basename)
    hint = (
        f" The newest run that does is {layout.run_id} — pass `--run "
        f"{layout.run_id}` to verify that one deliberately."
        if layout is not None else " No run has one; run `triage` first."
    )
    raise JoinError(
        f"the newest run {newest.run_id} has no {basename}.{hint}"
    )


__all__ = [
    'dry_run',
    'build_parser',
    'main',
    '_find_correlation',
]
