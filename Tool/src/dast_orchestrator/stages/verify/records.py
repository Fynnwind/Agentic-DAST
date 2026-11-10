"""The bounded verification loop and the record / summary / artifact writers.

Runs one loop per selected finding within a budget (:func:`verify_all`,
:func:`run_loop`), turns each outcome into a stored record, assembles
``verification.json`` and its printed summary, and builds the per-finding
contexts the loop reasons from. Depends on ``common`` and ``probes``.
"""
from __future__ import annotations
import dataclasses
import json
import re
import time
from contextlib import AsyncExitStack
from typing import Any, Iterable
import anyio
import anyio.to_thread
from dast_orchestrator.foundation import config
from dast_orchestrator.analysis import join
from dast_orchestrator.foundation import run_paths
from dast_orchestrator.adapters import targets
from dast_orchestrator.foundation import ui
from dast_orchestrator.domain import verification
from dast_orchestrator.analysis import verify_loop
from dast_orchestrator.adapters import retrieval as retrieval_mod
from dast_orchestrator.foundation import prompts as prompts_mod
from dast_orchestrator.foundation import metrics as run_metrics
from dast_orchestrator.analysis.join import JoinError
from dast_orchestrator.analysis.screening import LlmError, OpenRouterCorrelator
from dast_orchestrator.domain.verification import (
    CONFIRMED,
    DispatchBudget,
    INCONCLUSIVE,
    NOT_ATTEMPTED,
    REFUTED,
    RoundRecord,
)
from .common import *
from .probes import *

#: The prompt version this process's loop is running, set once by :func:`main`
#: so the artifact's metadata block names the file that was actually sent rather
#: than whatever is newest on disk at write time. ``None`` in the
#: fully-deterministic configuration, which sends no prompt.
_loop_prompt: "prompts_mod.Prompt | None" = None

#: Why a flagged finding was not dispatched, in the artifact's own words. Each
#: is a decision the pipeline made, not a failure — and each is a different one,
#: which a single "not dispatchable" message could not say.
_REFUSAL_DETAIL = {
    PATH_NOT_MARKABLE:
        "flagged, and the injection point is a path segment that no route "
        "template could mark safely — so sqlmap has nothing to aim at. A tool "
        "was named; this is a refusal to probe, not a rule the table cannot "
        "route",
    PARAM_NOT_IN_TOOLS_REQUEST:
        "flagged on a parameter that is in the request BODY, and this tool "
        "sends only a URL — sqlmap is the one wrapper that carries a body. So "
        "the tool would have fuzzed the query string and reported a verdict on "
        "that, filed against a body field it never touched. Refused before "
        "dispatch: measured 2026-09-08, this was 6 of the WordPress baseline's "
        "15 refutations",
    PARAM_NOT_IN_REQUEST:
        "flagged, but the parameter sqlmap would test is in neither the URL's "
        "query string nor the request body, and the URL carries no marked "
        "injection point — so there is nothing for it to address. Refused "
        "before dispatch: sqlmap does not fail loudly on this, it reports that "
        "the target may have rejected the probe, which reads like a fact about "
        "the application rather than about the request",
    URL_NONE_RECORDED:
        "flagged, but the alert records no example URL to aim a tool at",
    URL_PAYLOAD_UNRECOVERABLE:
        "flagged, but the recorded URL carries the attack payload in a path "
        "segment and the alert does not say what that segment held before it — "
        "probing it would test the payload, not the endpoint",
}


def _refusal_detail(refusal: "str | None") -> str:
    """The prose behind a not-attempted, per cause.

    The fallback used to read "no dispatchable tool, no concrete URL, or no
    markable path injection point" — three causes in one sentence, which is why
    nobody noticed that on the WordPress baseline it almost always meant the
    first one. It now names that case, and the categorical code beside it
    (:data:`verification.NA_NO_TOOL`) makes it countable.
    """
    if refusal in _REFUSAL_DETAIL:
        return _REFUSAL_DETAIL[refusal]
    return ("flagged for verification, but NO ARM NAMED A TOOL that could "
            "settle it — the rule is not in the rescan table (so it escalated "
            "on risk alone) or the table names no tool for it. Nothing was "
            "tested; this is not a clean result.")


def directed_arguments(finding: dict[str, Any], tool: str,
                       proposal: dict[str, Any],
                       findings_by_endpoint: dict[Any, list[dict[str, Any]]],
                       fillers: dict[str, str] | None,
                       auth_ctx: dict[str, Any] | None,
                       oob: bool) -> dict[str, Any] | None:
    """Executor arguments for one model-directed round, target derived deterministically.

    The model directs the invocation and may set param/method/data/tags/level/risk
    (already validated by
    :func:`~dast_orchestrator.domain.verification.validate_probe`); the **target is
    derived here**, exactly as the deterministic configuration derives it, so no
    round can ever point a tool at a host it was not asked about. That split —
    the model chooses how to look, the executor decides where — is what makes an
    unattended loop safe to give command authority at all.

    Returns ``None`` when no probeable URL exists: the same refusal the
    deterministic path records, and recorded as ``not-attempted`` rather than
    probed anyway.
    """
    probe = probe_target(finding, fillers)
    if not probe.probeable:
        return None
    alert = finding.get("alert") or {}
    target, param = probe.url, probe.param
    method = str(proposal.get("method") or alert.get("method")
                 or finding.get("method") or "GET").upper()
    # Mark a path injection point when the finding has one and the model either
    # asked for it outright (`path_injection`) or named no parameter. The
    # explicit ask matters: a model that has read the route knows the injectable
    # position is a path segment long before it can prove it, and until it had a
    # field to say so, setting `param` silently switched this off — so the one
    # correction it most wanted to make was the one it could not.
    wants_path = (proposal.get("path_injection")
                  or not proposal.get("param"))
    if tool == "sqlmap" and probe.injection_point == INJECT_PATH and wants_path:
        marked = mark_path_injection(target, param, str(finding.get("endpoint_key") or ""))
        if marked is None:
            return None
        target, param = marked, ""
    args: dict[str, Any] = {
        "target": target,
        # A marked path leaves no name to pass to `-p`, so a proposed parameter
        # is deliberately dropped there rather than fighting the marker.
        "param": "" if not param and proposal.get("path_injection")
                 else (proposal.get("param") or param),
        "method": method,
    }
    for key in ("data", "tags", "level", "risk"):
        if proposal.get(key) not in (None, ""):
            args[key] = proposal[key]
    # `path_injection` is an instruction to this function, not an argument for
    # the wrapper — it has already been honoured above.
    args.pop("path_injection", None)
    if tool == "sqlmap" and method != "GET" and "data" not in args:
        drop = {(auth_ctx or {}).get("session_cookie", "")} - {""}
        args["data"] = _form_body(findings_by_endpoint, finding, fillers or {}, drop)
    if tool == "nuclei":
        args.setdefault("oob", oob)
    if tool == "sqlmap" and not sqlmap_can_address(
            str(args.get("target") or ""), str(args.get("param") or ""),
            str(args.get("data") or "")):
        # Same refusal as the deterministic path. The model may name any
        # parameter it likes; it may not spend a dispatch on one that is in
        # neither the URL nor the body.
        return None
    _apply_auth(tool, args, method, auth_ctx)
    return args


def _synthesis_not_attempted_detail(claim: dict[str, Any]) -> str:
    """Why a synthesis claim was not dispatched — testability, not a failure."""
    tool = str(claim.get("suggested_tool") or "")
    if tool in verification.SYNTH_SELF_EVIDENT:
        return "self-evident: provable from its cited findings, no probe needed"
    if tool == verification.SYNTH_OUT_OF_SCOPE:
        return "out of scope for automated verification — manual evaluation"
    return "no supporting finding with a probeable URL to anchor the probe"

def _synthesis_not_attempted_code(claim: dict[str, Any]) -> str:
    """Whether a claim went unprobed by DECISION or for want of an anchor.

    `self-evident` and `out-of-scope` are dispositions the synthesis pass is
    required to justify, and a claim carrying one is not a routing gap. Counting
    them as :data:`~dast_orchestrator.domain.verification.NA_NO_TOOL` put 9 of the
    WordPress baseline's 11 under a warning that says each is a rule the rescan
    table does not route.
    """
    tool = str(claim.get("suggested_tool") or "")
    if tool in verification.SYNTH_SELF_EVIDENT or tool == verification.SYNTH_OUT_OF_SCOPE:
        return verification.NA_BY_DISPOSITION
    return verification.NA_NO_PROBE


def loop_config(invocation: str = "llm",
                max_rounds: int = verification.DEFAULT_MAX_ROUNDS) -> dict[str, Any]:
    """The invocation axis plus the round cap, as one block recorded on every record.

    Kept as a dict rather than scattered arguments because it is what a row of
    the comparison table *is*: a verification configuration. The two that matter
    are ``deterministic`` (the free control — no key, no spend) and ``llm`` (the
    default, the model directing each round). ``tool_choice`` is recorded as the
    constant ``table`` for provenance: the model-picks-the-tool axis was removed
    2026-11-02, so the lookup is the only tool choice there is.
    """
    return {"tool_choice": "table", "invocation": invocation,
            "max_rounds": int(max_rounds)}


async def run_loop(
    dispatcher: "Dispatcher",
    finding: dict[str, Any],
    plan: "dict[str, Any] | None",
    ctx: dict[str, Any],
    cfg: dict[str, Any],
    client: "OpenRouterCorrelator | None",
    findings_by_endpoint: dict[Any, list[dict[str, Any]]],
    fillers: "dict[str, str] | None" = None,
    auth_ctx: "dict[str, str] | None" = None,
    oob: bool = False,
    system_prompt: "str | None" = None,
    oracle: "dict[str, Any] | None" = None,
    retrieval: "retrieval_mod.Retrieval | None" = None,
    session: Any = None,
) -> verification.LoopVerdict:
    """Verify one finding: up to ``max_rounds`` tool invocations, then a verdict.

    ``plan`` is the deterministic dispatch for this finding — the tool the table
    chose and the invocation it would build. It plays two different roles
    depending on the invocation axis:

    * ``invocation=deterministic`` — the plan *is* the probe. One round, no
      model, no key. This is the fully-deterministic control, and it must stay
      first-class: without a deterministic path in every comparison, "the model
      verifies well" is unfalsifiable.
    * ``invocation=llm`` — the plan supplies the tool (the deterministic lookup)
      and nothing else; the model directs each round and decides when it is
      confident.

    ``None`` means no arm named a dispatchable tool, or no URL could be derived
    that would answer a question about the endpoint rather than about a previous
    tool's payload. Recorded as ``not-attempted`` with the reason, never
    silently dropped and never probed anyway.
    """
    finding_id = str(finding.get("finding_id") or "")
    # The alert threads into every `settle` below so a confirmed verdict is gated
    # on class agreement where the verdict is formed, not patched afterward.
    alert = finding.get("alert") or {}
    if plan is None or plan.get("tool") is None:
        # Two different failures, and conflating them is what hid the rule-40026
        # defect: `plan is None` means NO ARM NAMED A TOOL — the table asked for
        # a rescan it cannot route — while a plan with `tool: None` means a tool
        # was named and no honest URL could be built for it.
        refusal = (plan or {}).get("refusal")
        if plan is None:
            # NO ARM NAMED A TOOL — the table asked for a rescan it cannot
            # route. Conflating this with the two below is what hid the
            # rule-40026 defect.
            code = verification.NA_NO_TOOL
        elif refusal in PARAM_REACH_REFUSALS:
            # A tool was named and a clean URL was built, and the parameter is
            # still not in the request that tool sends. Not `no-probe-url`: the
            # URL is fine, the question cannot be put.
            code = verification.NA_TOOL_CANNOT_REACH
        else:
            code = verification.NA_NO_PROBE
        return verify_loop.unattempted(
            finding_id, _refusal_detail(refusal), code=code)

    plugin_id = str(plan.get("plugin_id") or "")
    if cfg["invocation"] == "deterministic" or client is None:
        # Single-shot by nature: the deterministic side never loops. There is
        # nothing to react to, because nothing about the invocation would change.
        result = await dispatcher.run(plan["tool"], plan["arguments"], plugin_id)
        if result.get("outcome") == verification.NOT_ATTEMPTED:
            # The budget refused it before the tool ran. That is a third cause of
            # `not-attempted`, and it has to be countable beside the other two —
            # a finding the cap dropped and one nothing could ever test are not
            # the same fact. See `verification.NA_REASONS`.
            return verify_loop.unattempted(
                finding_id, str(result.get("detail") or "budget"),
                code=verification.NA_CAPPED)
        record = _round_record(1, plan["tool"], plan["arguments"],
                               verification.DeclaredSignal(), result)
        return verify_loop.settle(
            finding_id, [record], None,
            "deterministic invocation: one probe, no loop", alert=alert)

    fixed_tool = plan["tool"]
    context = verify_loop.build_context(
        finding, ctx.get("exchange"), ctx.get("source"),
        fixed_tool=fixed_tool, max_rounds=cfg["max_rounds"], oracle=oracle,
        # Only ever reaches the model in oracle mode — `build_context` drops it
        # otherwise, so the blind loop's independence is not on this call site.
        earlier_triage=verify_loop.triage_view(finding))
    conversation = verify_loop.build_messages(context, system_prompt)

    # In pull mode the model may ask the read-only context server for more of the
    # handler source mid-loop, exactly as triage's pull path does. The session is
    # this finding's own (opened and closed by `verify_all`); push mode — the
    # default — leaves it None and the loop reasons from what `build_context`
    # pushed. `retrieval` carries the tool contract and per-finding call ceiling.
    retrieval_tools = retrieval.tools if retrieval is not None else None
    max_retrievals = retrieval.max_calls if retrieval is not None else 0

    rounds: list[RoundRecord] = []
    for index in range(1, cfg["max_rounds"] + 1):
        last = index == cfg["max_rounds"]
        try:
            raw = client.complete(
                conversation, schema_name="dast_verify_round",
                schema=verify_loop.ROUND_SCHEMA,
                schema_description=(
                    "One round: the invocation to run and the signal it would "
                    "show, or the category this finding settles at."
                ),
                pass_name="verify_loop", label=f"{finding_id}#{index}",
                max_tokens=verify_loop.ROUND_MAX_TOKENS,
                # Everything but the newest tool result was sent verbatim last
                # round, so that is the prefix worth caching — and it is the
                # large half: the system prompt plus the task block carrying the
                # handler source dwarfs one round's output. Round 1 has no
                # prefix to reuse.
                cache_prefix=len(conversation) - 1 if index > 1 else 0,
                cache_site="verify",
                retrieval=session,
                retrieval_tools=retrieval_tools,
                max_retrievals=max_retrievals,
            )
        # Deliberately broader than LlmError. A finding is ONE unit of work, and
        # losing an entire stage — with its scan and triage already paid for —
        # because one model call failed is out of all proportion to the failure.
        # The artifact has an honest way to record it either way, so the
        # exception is turned into a verdict rather than an exit. Cancellation
        # is a BaseException and still propagates, so a stopped run still stops.
        except Exception as exc:
            # The type is carried into the record, not just the message: on its
            # own "Server disconnected without sending a response" does not say
            # whether the model refused, the schema failed, or the transport
            # dropped — and those need different responses from a reader.
            why = f"{type(exc).__name__}: {exc}"
            _loop_warn(f"loop — {finding_id}: round {index} not answered ({why})")
            if rounds:
                # Rounds already ran, so there IS tool evidence; settling on it
                # with no model category leaves the wrapper's reading as the
                # verdict, which is honest. Losing it would throw away work the
                # budget already paid for.
                return verify_loop.settle(finding_id, rounds, None,
                                          f"model stopped answering ({why})",
                                          alert=alert)
            return verify_loop.unattempted(
                finding_id, f"the model never proposed a probe ({why})",
                code=verification.NA_NO_PROBE)

        proposal = verify_loop.normalise_round(raw, fixed_tool, last)
        # A `conclude` after the first round carries no new probe: it is the
        # model reading the output it was just handed. Running one anyway would
        # spend the budget on a question already answered, and would leave the
        # wrapper auditing a different call than the model read.
        if proposal["action"] == "conclude" and rounds:
            return verify_loop.settle(finding_id, rounds, proposal["category"],
                                      f"model concluded at round {index}",
                                      alert=alert)
        if not proposal["executable"]:
            if rounds:
                return verify_loop.settle(
                    finding_id, rounds, proposal["category"] or INCONCLUSIVE,
                    "model proposed no executable invocation", alert=alert)
            return verify_loop.unattempted(
                finding_id, "no executable probe proposed: "
                            + "; ".join(proposal["violations"]),
                code=verification.NA_NO_PROBE)

        args = directed_arguments(finding, proposal["tool"], proposal["arguments"],
                                  findings_by_endpoint, fillers, auth_ctx, oob)
        if args is None:
            if rounds:
                return verify_loop.settle(
                    finding_id, rounds, proposal["category"] or INCONCLUSIVE,
                    "no probeable URL for the proposed invocation", alert=alert)
            return verify_loop.unattempted(
                finding_id, "no probeable URL to aim the proposed tool at",
                code=verification.NA_NO_PROBE)

        result = await dispatcher.run(proposal["tool"], args, plugin_id)
        signal = verification.DeclaredSignal.from_dict(proposal["signal"])
        record = _round_record(index, proposal["tool"], args, signal, result,
                               note=proposal["note"] or proposal["reasoning"],
                               category=proposal["category"],
                               violations=tuple(proposal["violations"]),
                               model_directed=True)
        rounds.append(record)

        if record.wrapper_outcome == NOT_ATTEMPTED:
            # The budget refused this round. Asking the model again would spend
            # money proposing probes nothing will run, so the loop ends here and
            # settles on the evidence it already has.
            return verify_loop.settle(
                finding_id, rounds, proposal["category"],
                f"budget refused round {index}: "
                + str((record.tool_result or {}).get("detail", "")), alert=alert)

        # A conclusion reached on the FIRST round is a pre-commitment: the model
        # named a probe and the category it expects that probe to produce, and
        # it is honoured only after the probe has actually run. That is the
        # declared signal's logic applied to the category itself, and it is
        # falsifiable in the same way.
        if proposal["action"] == "conclude":
            return verify_loop.settle(finding_id, rounds, proposal["category"],
                                      f"model concluded at round {index}",
                                      alert=alert)
        if proposal["forced"]:
            # The model wanted another round and there is none. Its last probe
            # ran; what it would have made of the result is unknown, so no
            # category is recorded for it.
            return verify_loop.settle(
                finding_id, rounds, None,
                f"round cap ({cfg['max_rounds']}) reached before the model concluded",
                alert=alert)
        conversation.append(
            verify_loop.round_result_message(record, cfg["max_rounds"] - index))

    return verify_loop.settle(finding_id, rounds, rounds[-1].model_category,
                              f"round cap ({cfg['max_rounds']}) reached", alert=alert)


def _round_record(index: int, tool: str, arguments: dict[str, Any],
                  signal: verification.DeclaredSignal,
                  result: dict[str, Any], note: str = "",
                  category: "str | None" = None,
                  violations: tuple[str, ...] = (),
                  model_directed: bool = False) -> RoundRecord:
    """One round, with the wrapper's reading of its output taken on the spot.

    The wrapper classification is computed here, per round, and not only for the
    round the model happened to stop on — so the *trajectory* of a loop is
    visible, and a finding whose verdict came only after a corrected invocation
    is distinguishable from one that was settled first time.
    """
    check = verification.check_signal(signal, result)
    return RoundRecord(
        index=index,
        tool=tool,
        arguments=dict(arguments),
        declared_signal=signal.as_dict(),
        signal_check=check.as_dict(),
        wrapper_outcome=str(result.get("outcome") or INCONCLUSIVE),
        tool_ran=verification.tool_ran(result),
        tool_result={k: result.get(k) for k in
                     ("outcome", "evidence", "detail", "command", "exit_code",
                      "seconds", "timed_out", "tool_warnings", "tested",
                      "stdout_excerpt", "stderr_excerpt", "matched_templates")},
        model_note=note,
        model_category=category,
        violations=violations,
        model_directed=model_directed,
    )


async def verify_all(
    dispatchable: list[dict[str, Any]],
    correlated_plans: list[tuple[dict[str, Any], dict[str, Any] | None]],
    budget: DispatchBudget,
    findings_by_endpoint: dict[Any, list[dict[str, Any]]],
    cfg: dict[str, Any],
    client: "OpenRouterCorrelator | None" = None,
    findings_by_id: "dict[str, dict[str, Any]] | None" = None,
    fillers: "dict[str, str] | None" = None,
    auth_ctx: "dict[str, str] | None" = None,
    oob: bool = False,
    contexts: "dict[str, dict[str, Any]] | None" = None,
    system_prompt: "str | None" = None,
    target: "targets.Target | None" = None,
    max_siblings: int = DEFAULT_MAX_SIBLINGS,
    oracle: "dict[str, Any] | None" = None,
    check_route: "Any | None" = None,
    retrieval: "retrieval_mod.Retrieval | None" = None,
    oracle_seed_markers: "list[Any] | None" = None,
    run_auth_mode: str = "none",
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]],
           dict[str, int], dict[str, Any], list[dict[str, Any]]]:
    """Run one loop per selected finding, all within one dispatcher and budget.

    Replaces the old two-pass shape (deterministic dispatch, then a directed arm
    beside it, then a residue pass over what was left) with one loop whose
    configuration says how much of it the model drives. There is no second arm
    to run afterwards: the wrapper's reading of each round rides along free, and
    the independent control is a *separate run* at
    :data:`~dast_orchestrator.domain.verification.DETERMINISTIC_CONFIG`, not a second
    dispatch inside this one.

    ``oracle_seed_markers`` turns on the oracle-seeded dispatch (the driver passes
    the target's markers only under ``--oracle`` + ``VERIFY_ORACLE_SEED_DISPATCH``,
    else ``None``). It runs after the two loops above, is a sixth return value of
    its own, and is gated here a second time on the oracle block so it can never
    fire blind. ``run_auth_mode`` (the run's ``--auth``) gates which markers are
    seeded: one above the run's auth is skipped, matching the detection layer's
    not-applicable (auth) rule. Each seeded probe dispatches off-budget so the
    finding loop's spent budget cannot starve it. See the oracle-seed block below.
    """
    contexts = contexts or {}
    verifications: list[dict[str, Any]] = []
    correlated_out: list[dict[str, Any]] = []
    siblings_out: list[dict[str, Any]] = []
    oracle_seeded_out: list[dict[str, Any]] = []
    # Routes this run is already verifying per endpoint. A propagation claim
    # must not re-probe one of them: the same route would be tested twice and
    # the two verdicts counted as independent evidence.
    verified_routes = {
        str(f.get("endpoint_key") or f"{f.get('method')} {f.get('path')}")
        for f in dispatchable
    }
    agreement = verify_loop.empty_agreement()
    signals = verify_loop.signal_counts([])
    looped = rounds_run = tool_rounds = 0
    looping = client is not None and cfg["invocation"] == "llm"
    budget_for_model = verify_loop.MAX_LOOPED_FINDINGS

    ui.step(f"configuration: invocation {cfg['invocation']}"
            + (f", up to {cfg['max_rounds']} round(s)" if looping else ""))

    # One bar over the whole selected population, on top of the per-finding rows
    # (like the ZAP stages) — how far through the dispatch we are, and roughly
    # how long is left. Siblings are extra probes within a claim, so they add a
    # row without advancing the count.
    total = len(dispatchable) + len(correlated_plans)
    global _BAR
    progress = _BAR = ui.Progress("verify", step=0)
    started = time.monotonic()
    done = 0

    def _advance(verdict: verification.LoopVerdict) -> None:
        nonlocal done
        done += 1
        progress.line(_verdict_line(verdict),
                      (done * 100 // total) if total else 100,
                      time.monotonic() - started)

    async with AsyncExitStack() as stack:
        dispatcher = Dispatcher(budget, stack)

        for finding in dispatchable:
            plan = build_dispatch(finding, findings_by_endpoint, fillers,
                                  auth_ctx, oob, oracle=bool(oracle))
            # The model budget is spent only where a model call can actually
            # lead to a tool run. Two ways it cannot, and BOTH were silently
            # burning it: a finding no arm routed to a tool (576 of 604 on the
            # WordPress corpus, and they sort among the rest), and one whose
            # rule has already hit its per-rule cap. Asking the model to propose
            # a probe the executor will refuse costs real money for a proposal
            # that is discarded unread.
            use_client = None
            if looping and budget_for_model > 0 and _can_dispatch(dispatcher, plan):
                use_client = client
                budget_for_model -= 1
            session = (retrieval.session(str(finding.get("finding_id") or ""))
                       if retrieval is not None and use_client is not None else None)
            try:
                verdict = await run_loop(
                    dispatcher, finding, plan, contexts.get(finding["finding_id"], {}),
                    cfg, use_client, findings_by_endpoint, fillers, auth_ctx, oob,
                    # `oracle` is forwarded exactly as the claim loop below does:
                    # in a ceiling run `build_context` puts the advisory and the
                    # earlier-triage view into the finding's task (it drops both
                    # when `oracle` is None, so a blind run stays independent).
                    system_prompt, oracle=oracle, retrieval=retrieval, session=session,
                )
            finally:
                if session is not None:
                    session.close()
            verifications.append(_record(finding, verdict, cfg))
            looped += bool(verdict.rounds and use_client is not None)
            rounds_run += verdict.rounds_used
            tool_rounds += _tool_rounds(verdict)
            _count_agreement(agreement, verdict)
            _add_signals(signals, verdict)
            _advance(verdict)

        for correlated, plan in correlated_plans:
            support = (findings_by_id or {}).get(plan.get("via_finding_id", "")) \
                if plan else None
            use_client = None
            if looping and budget_for_model > 0 and _can_dispatch(dispatcher, plan):
                use_client = client
            if plan is None:
                verdict = verify_loop.unattempted(
                    correlated["finding_id"],
                    _synthesis_not_attempted_detail(correlated),
                    code=_synthesis_not_attempted_code(correlated))
            else:
                if use_client is not None:
                    budget_for_model -= 1
                # A synthesis claim names route templates, not one alert, so the
                # loop is anchored on a concrete finding the claim cites — the
                # closest honest probe of a cross-endpoint claim.
                session = (retrieval.session(str(correlated.get("finding_id") or ""))
                           if retrieval is not None and use_client is not None
                           else None)
                try:
                    verdict = await run_loop(
                        dispatcher, support or {}, plan,
                        contexts.get(plan.get("via_finding_id", ""), {}),
                        cfg, use_client, findings_by_endpoint, fillers, auth_ctx,
                        oob, system_prompt, oracle, retrieval=retrieval,
                        session=session,
                    )
                finally:
                    if session is not None:
                        session.close()
                verdict = _renamed(verdict, correlated["finding_id"])
            correlated_out.append(_correlated_record(correlated, plan, verdict, cfg))
            looped += bool(verdict.rounds and use_client is not None)
            rounds_run += verdict.rounds_used
            tool_rounds += _tool_rounds(verdict)
            _count_agreement(agreement, verdict)
            _add_signals(signals, verdict)
            _advance(verdict)

            # The dispatch half of the claim: the routes it PREDICTS, which the
            # anchor probe above never touches. Single-shot and deterministic —
            # the invocation is fully determined by the route and the anchor's
            # parameter, there is nothing for a model to direct, and this way
            # sibling verification works in the fully-deterministic
            # configuration too.
            for probe in build_sibling_dispatches(
                    correlated, plan, support, target, verified_routes,
                    max_siblings, auth_ctx, oob):
                url = str(probe["arguments"]["target"])
                # Does this route exist at all? The URL was BUILT from a route
                # template, so a probe at one the application does not serve
                # refutes the URL and says nothing about the claim. One clean GET
                # settles it before a real probe
                # is spent. Off the event loop, because the transport is a
                # blocking one-shot container.
                status = (await anyio.to_thread.run_sync(check_route, url)
                          if check_route is not None else None)
                blocked = verification.route_probeable(status)
                if blocked is not None:
                    record = sibling_record(
                        probe,
                        {"outcome": blocked,
                         "detail": _SIBLING_BLOCKED_DETAIL[blocked].format(
                             status=status)},
                        correlated, cfg, route_status=status)
                else:
                    result = await dispatcher.run(
                        probe["tool"], probe["arguments"],
                        str(probe.get("plugin_id") or ""), exempt_per_rule=True)
                    record = sibling_record(probe, result, correlated, cfg,
                                            route_status=status)
                siblings_out.append(record)
                tool_rounds += int(record["outcome"] not in _SIBLING_UNPROBED)
                progress.line(_sibling_line(record))

        # The oracle-seeded dispatch (VERIFY_ORACLE_SEED_DISPATCH), gated on the
        # oracle block being present — belt-and-braces with the driver's own flag
        # gate, the same invariant `build_context` keeps for the finding loop, so
        # it can NEVER fire in a blind run. For every marker whose documented sink
        # the scan raised no finding for, synthesise one single-shot probe at that
        # sink and settle it through `resolve_verdict` exactly as the deterministic
        # arm does. `target is not None` because the probe URL is built from it.
        if oracle and oracle_seed_markers and target is not None:
            from dast_orchestrator.stages import ground_truth as _gt  # noqa: PLC0415
            # A marker is "already covered" when a selected finding carries one of
            # its rules — the normal path routed a dispatch to the sink, so seeding
            # a second probe there would double-count. When the rule fired 0× (the
            # miss this remediates) no finding carries it, so the marker is seeded.
            covered_rules = {str((f.get("alert") or {}).get("plugin_id") or "")
                             for f in dispatchable}
            for marker in oracle_seed_markers:
                # Only seed a marker the run's auth mode can actually reach
                # (none < user < admin) — the same rule the detection layer uses
                # for not-applicable (auth). A marker above the run's auth is
                # neither probed nor recorded, so a miss an auth level prevented
                # never appears as an oracle-seeded not-attempted/refuted.
                if not _gt.auth_applicable(marker.auth, run_auth_mode):
                    continue
                if set(marker.zap_rules) & covered_rules:
                    continue
                plan = build_oracle_seed_dispatch(marker, target, auth_ctx, oob)
                if plan is None:
                    # The marker's rule routes to no dispatchable tool — nothing
                    # to probe its sink with, so it is left unseeded.
                    continue
                # Off-budget: the finding loop above may have spent the run-total
                # dispatch cap, but this one bounded probe at a sink the loop
                # never reached must not be starved by it (nor by the wall clock).
                result = await dispatcher.run(
                    plan["tool"], plan["arguments"],
                    str(plan.get("plugin_id") or ""),
                    exempt_per_rule=True, off_budget=True)
                record = _round_record(1, plan["tool"], plan["arguments"],
                                       verification.DeclaredSignal(), result)
                verdict = verify_loop.settle(
                    f"o-{marker.id}", [record], None,
                    "oracle-seeded dispatch: one probe at the marker's own sink, "
                    "no loop", alert=plan["alert"])
                oracle_seeded_out.append(_oracle_seed_record(plan, verdict, cfg))
                tool_rounds += _tool_rounds(verdict)
                progress.line(_oracle_seed_line(verdict, str(marker.id)))

        per_rule_final = dict(dispatcher.per_rule)
    progress.close()
    _BAR = None

    info: dict[str, Any] = {
        "config": cfg, "findings_looped": looped, "rounds_run": rounds_run,
        # Rounds in which a tool was actually invoked. Distinct from
        # `rounds_run`, which also counts the rounds a budget refused before
        # anything ran — those are loop iterations, not tool work, and reporting
        # them as one number overstated the stage's dispatch by a third on the
        # first live run (38 "rounds" for 17 invocations).
        "tool_rounds": tool_rounds,
        "agreement": agreement,
        "signals": signals,
        # What the model was offered and what it pulled, or that nothing was —
        # an experiment about what a verifier chooses to ask for is unauditable
        # without the list. Mirrors triage's pull provenance.
        "retrieval": (retrieval.as_dict() if retrieval is not None
                      else {"mode": retrieval_mod.PUSH_MODE}),
    }
    if client is not None:
        info["metadata"] = verify_loop.run_metadata(
            client.model, client.usage, cfg, looped, rounds_run, agreement,
            prompt=_loop_prompt, capabilities=client.capabilities)
    return (verifications, correlated_out, siblings_out, per_rule_final, info,
            oracle_seeded_out)


def _can_dispatch(dispatcher: "Dispatcher",
                  plan: "dict[str, Any] | None") -> bool:
    """Could a probe for this plan actually run right now?

    Asked *before* the model is called, not after. The budget is enforced inside
    :meth:`Dispatcher.run`, which is the right place for it — but by the time it
    says no, an LLM configuration has already paid for a proposal that will be
    discarded. On a corpus where most findings route nowhere, that is the whole
    model budget spent on findings no tool was ever going to touch.
    """
    if plan is None or plan.get("tool") is None:
        return False
    return dispatcher.can_dispatch(str(plan.get("plugin_id") or ""))


def _add_signals(totals: dict[str, int],
                 verdict: verification.LoopVerdict) -> None:
    for key, value in verify_loop.signal_counts(list(verdict.rounds)).items():
        totals[key] = totals.get(key, 0) + value


def _tool_rounds(verdict: verification.LoopVerdict) -> int:
    """Rounds of this loop in which a tool was actually invoked."""
    return sum(1 for r in verdict.rounds if r.wrapper_outcome != NOT_ATTEMPTED)


def _count_agreement(agreement: dict[str, int],
                     verdict: verification.LoopVerdict) -> None:
    """Count a record's agreement **only where there were two readers**.

    A record with no model category has nothing to agree or disagree with, and
    counting it as agreement is not a harmless default: the first live
    deterministic run reported *"614 agree / 0 flagged (0.0%)"* for a
    configuration that never called a model. Read off a comparison sheet, that
    0% sits in the same column as the LLM rows' real disagreement rate and
    invites exactly the wrong conclusion — that the deterministic arm agrees
    with a model it never consulted.
    """
    if verdict.llm_verdict is None:
        return
    agreement[verdict.agreement] = agreement.get(verdict.agreement, 0) + 1


def _renamed(verdict: verification.LoopVerdict,
             finding_id: str) -> verification.LoopVerdict:
    """The same verdict under the claim's own id, not the anchor finding's."""
    return dataclasses.replace(verdict, finding_id=finding_id)


def _record(finding: dict[str, Any], verdict: verification.LoopVerdict,
            cfg: dict[str, Any]) -> dict[str, Any]:
    """One finding's verification record: both readings, the reported one, the trace."""
    alert = finding.get("alert") or {}
    final = verdict.rounds[-1] if verdict.rounds else None
    result = (final.tool_result if final else {}) or {}
    record: dict[str, Any] = {
        "finding_id": verdict.finding_id,
        "plugin_id": str(alert.get("plugin_id") or ""),
        "rule_name": str(alert.get("name") or ""),
        "risk": str(alert.get("risk") or ""),
        "deterministic_flagged": bool(
            (finding.get("deterministic") or {}).get("needs_rescan")),
        "llm_flagged": bool((finding.get("llm") or {}).get("needs_rescan")),
        "tool": verdict.tool,
        # `outcome` stays the reported verdict under its long-standing name, so
        # every downstream reader — SARIF, ground truth, the summary — keeps
        # working against one field that means "what this layer concluded".
        "outcome": verdict.reported,
        "detail": verdict.detail,
        "evidence": result.get("evidence"),
        "config": cfg,
        **verdict.as_dict(),
    }
    if final is not None:
        record.update({
            "target": (final.arguments or {}).get("target", ""),
            "param": (final.arguments or {}).get("param", ""),
            "method": (final.arguments or {}).get("method", "GET"),
            **{k: result[k] for k in
               ("command", "exit_code", "seconds", "timed_out", "tool_warnings",
                "matched_templates", "stdout_excerpt", "stderr_excerpt")
               if result.get(k) is not None},
        })
    return record


def _correlated_record(correlated: dict[str, Any], plan: "dict[str, Any] | None",
                       verdict: verification.LoopVerdict,
                       cfg: dict[str, Any]) -> dict[str, Any]:
    final = verdict.rounds[-1] if verdict.rounds else None
    result = (final.tool_result if final else {}) or {}
    record: dict[str, Any] = {
        "finding_id": verdict.finding_id,
        "pattern": correlated.get("pattern"),
        "suggested_tool": correlated.get("suggested_tool"),
        "via_finding_id": (plan or {}).get("via_finding_id"),
        "tool": verdict.tool,
        "outcome": verdict.reported,
        "detail": verdict.detail,
        "evidence": result.get("evidence"),
        "config": cfg,
        **verdict.as_dict(),
    }
    if final is not None:
        record["target"] = (final.arguments or {}).get("target", "")
        record["method"] = (final.arguments or {}).get("method", "GET")
    return record


def _oracle_seed_record(plan: dict[str, Any], verdict: verification.LoopVerdict,
                        cfg: dict[str, Any]) -> dict[str, Any]:
    """One oracle-seeded marker probe's verdict, with provenance saying it was
    NOT derived from a ZAP alert.

    ``origin`` (:data:`ORIGIN_ORACLE_SEED`) and ``url_source``
    (:data:`URL_ORACLE_SEEDED`) mark it as synthesised from a ground-truth
    marker's own sink, so no reader mistakes it for a finding-derived probe or
    counts it among the blind detections. The reported verdict still came through
    :func:`~dast_orchestrator.domain.verification.resolve_verdict`, settled by the
    caller with the marker's rule as the alert so the class gate applies.
    """
    final = verdict.rounds[-1] if verdict.rounds else None
    result = (final.tool_result if final else {}) or {}
    record: dict[str, Any] = {
        "finding_id": verdict.finding_id,
        "origin": ORIGIN_ORACLE_SEED,
        "marker_id": plan.get("marker_id"),
        "cve": plan.get("cve"),
        "auth": plan.get("auth"),
        "plugin_id": plan.get("plugin_id"),
        "zap_rules": plan.get("zap_rules"),
        "sink": plan.get("sink"),
        "url_source": plan.get("url_source"),
        "tool": verdict.tool,
        "outcome": verdict.reported,
        "detail": verdict.detail,
        "evidence": result.get("evidence"),
        "config": cfg,
        # Said on the record, not left to a reader: this verdict is a CEILING
        # reading, aimed at a documented sink the scan never flagged.
        "found_by": {
            "layer": "oracle-seeded-verification",
            "mechanism": "marker-sink-probe",
            "tied_to_zap_alert": False,
            "how_to_read": (
                "A confirmation means an independent tool reproduced the "
                "documented CVE at its own sink, with the dispatch SYNTHESISED "
                "from the marker (VERIFY_ORACLE_SEED_DISPATCH) because no ZAP "
                "finding routed one there — the in-band scanner did not reach the "
                "sink within the active-scan cap. It is a ceiling reading of the "
                "verification layer, never a blind detection, and never belongs "
                "in the same column as one."
            ),
        },
        **verdict.as_dict(),
    }
    if final is not None:
        record.update({
            "target": (final.arguments or {}).get("target", ""),
            "param": (final.arguments or {}).get("param", ""),
            "method": (final.arguments or {}).get("method", "GET"),
            **{k: result[k] for k in
               ("command", "exit_code", "seconds", "timed_out", "tool_warnings",
                "matched_templates", "stdout_excerpt", "stderr_excerpt")
               if result.get(k) is not None},
        })
    return record


def _oracle_seed_line(verdict: verification.LoopVerdict, marker_id: str) -> str:
    """One row per oracle-seeded marker probe; a confirmation is loud."""
    mark = {CONFIRMED: "CONFIRMED", REFUTED: "refuted",
            INCONCLUSIVE: "inconclusive", NOT_ATTEMPTED: "not-attempted"}
    if verdict.reported == CONFIRMED:
        return (f"★ ORACLE-SEEDED CONFIRMED `{verdict.finding_id}` ({marker_id}) "
                f"via {verdict.tool} — the marker's own sink, no ZAP alert")
    outcome = mark.get(verdict.reported, verdict.reported)
    return (f"oracle-seed {(verdict.tool or '-'):<7} {marker_id:<22} → {outcome}")


#: Prose behind each pre-check refusal, per cause. Two causes, deliberately not
#: one message: "the route does not exist" is a result about the CLAIM, and "the
#: route exists but the probe would read another page" is a result about the
#: PROBE, and a reader has to be able to tell which they are looking at.
_SIBLING_BLOCKED_DETAIL = {
    verification.SIBLING_UNREACHABLE:
        "the constructed URL answered {status}: the route this claim predicted "
        "is not served, so there was nothing to probe and a refutation here "
        "would have been about the URL, not about the claim",
    verification.SIBLING_NOT_PROBEABLE:
        "the constructed URL answered {status}: the route is served, but a "
        "probe follows the redirect or reads the error page, so whatever it "
        "concluded would have been about THAT page. Measured 2026-09-08: all "
        "five served Gitea sibling routes answered 302 and all five probes "
        "came back refuted — of the login page",
}

#: Sibling outcomes that mean no tool was invoked. `NOT_ATTEMPTED` is a budget
#: or routing gap; the other two are pre-check refusals.
_SIBLING_UNPROBED = (NOT_ATTEMPTED, verification.SIBLING_UNREACHABLE,
                     verification.SIBLING_NOT_PROBEABLE)


def _sibling_line(record: dict[str, Any]) -> str:
    status = record.get("route_status")
    where = f" [{status}]" if status else ""
    line = (f"sibling  {(record.get('tool') or '-'):<7} {record['route']}{where} "
            f"→ {record['outcome']}")
    if record["outcome"] == verification.SIBLING_UNREACHABLE:
        # Not a failure and not a refutation: the route the claim predicted is
        # not served, so the prediction was about somewhere that does not exist.
        return f"{line} (constructed URL is not served — not probed)"
    if record["outcome"] == verification.SIBLING_NOT_PROBEABLE:
        # The route IS served; what the probe would have read is not its page.
        return (f"{line} (route answers {status}, so the probe would have read "
                "a redirect target or an error page — not probed)")
    if record["outcome"] == CONFIRMED:
        # Loud, because this is the headline: a real vulnerability at a route
        # the scan never flagged, reached by the LLM layer and by nothing else.
        return (f"★ CONFIRMED by propagation `{record['finding_id']}` at "
                f"{record['route']} ({record['target']}) — a route ZAP never "
                f"flagged. Predicted by claim {record['claim_id']}.")
    return line


#: The live dispatch bar, set for the length of the loop. A warning raised deep
#: inside a round (``_loop_warn``) routes through it so a stray line does not
#: desync the fixed header's line count; outside the loop it is ``None`` and a
#: warning is an ordinary ``ui.warn``.
_BAR: "ui.Progress | None" = None


def _loop_warn(message: str) -> None:
    if _BAR is not None:
        _BAR.line("! " + message)
    else:
        ui.warn(message)


def _verdict_line(verdict: verification.LoopVerdict) -> str:
    """One aligned row per finding: ``tool  finding-id  outcome  [note]``.

    Fixed-width columns so the eye reads down each one — the tool, the finding,
    the verdict — rather than parsing a sentence per line. Any disagreement is on
    the row rather than only in the artifact because it is the number this stage
    exists to produce: a run where the wrapper and the model read the same tool
    output differently on a third of the findings is a result, and it should be
    visible while the run is happening.
    """
    mark = {CONFIRMED: "CONFIRMED", REFUTED: "refuted",
            INCONCLUSIVE: "inconclusive", NOT_ATTEMPTED: "not-attempted"}
    note = ""
    if verdict.agreement == verification.FLAGGED:
        note = (f"   ← flagged: wrapper {verdict.wrapper_verdict}, "
                f"model {verdict.llm_verdict}")
    elif verdict.rounds_used > 1:
        note = f"   {verdict.rounds_used} rounds"
    outcome = mark.get(verdict.reported, verdict.reported)
    return (f"{(verdict.tool or '-'):<7} {verdict.finding_id:<15} "
            f"{outcome:<13}{note}")


# -- selection, summary, artifact ------------------------------------------


def select_findings(findings: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    """Findings either arm flagged, most-important-first."""
    flagged = [f for f in findings if verification.is_dispatchable(f)
               or (f.get("deterministic") or {}).get("needs_rescan")
               or (f.get("llm") or {}).get("needs_rescan")]
    return sorted(flagged, key=verification.dispatch_priority)


def summarise(verifications: list[dict[str, Any]],
              correlated: list[dict[str, Any]],
              per_rule: dict[str, int],
              loop_info: "dict[str, Any] | None" = None,
              siblings: "list[dict[str, Any]] | None" = None,
              oracle_seeded: "list[dict[str, Any]] | None" = None) -> dict[str, Any]:
    """The run's outcome counts, plus the two-reading agreement rate.

    ``by_wrapper_verdict`` sits beside ``by_outcome`` deliberately. The reported
    verdict is what the report acts on; the wrapper's reading of the same rounds
    is the deterministic control that rides along free, and keeping both counts
    is what makes "the model verifies well" a falsifiable claim rather than an
    assumption about a number nobody recorded.

    Sibling probes are counted **in their own block and never folded into
    ``by_outcome``**. They are a different population — no ZAP alert, a
    constructed URL, an asymmetric reading (see
    :func:`build_sibling_dispatches`) — and adding their refutations to the
    flagged tally would depress a refutation rate with probes of routes that may
    not exist, while adding their confirmations to it would credit the scanner
    with a route it never reached.
    """
    by_outcome: dict[str, int] = {}
    by_wrapper: dict[str, int] = {}
    by_tool: dict[str, dict[str, int]] = {}
    not_attempted: dict[str, int] = {}
    seconds = 0.0
    rounds_hist: dict[str, int] = {}
    for row in verifications + correlated:
        outcome = row.get("outcome", "?")
        by_outcome[outcome] = by_outcome.get(outcome, 0) + 1
        wrapper = row.get("wrapper_verdict")
        if wrapper:
            by_wrapper[wrapper] = by_wrapper.get(wrapper, 0) + 1
        tool = row.get("tool") or "none"
        by_tool.setdefault(tool, {}).setdefault(outcome, 0)
        by_tool[tool][outcome] += 1
        reason = row.get("not_attempted_reason")
        if reason:
            not_attempted[reason] = not_attempted.get(reason, 0) + 1
        used = str(row.get("rounds_used", 0))
        rounds_hist[used] = rounds_hist.get(used, 0) + 1
        for record in row.get("rounds") or []:
            secs = (record.get("tool_result") or {}).get("seconds")
            if isinstance(secs, (int, float)):
                seconds += float(secs)
    summary: dict[str, Any] = {
        "selected": len(verifications),
        "correlated_selected": len(correlated),
        "dispatched": sum(
            1 for r in verifications + correlated
            if r.get("outcome") != NOT_ATTEMPTED
        ),
        "by_outcome": by_outcome,
        "by_wrapper_verdict": by_wrapper,
        "by_tool": by_tool,
        # WHY the not-attempted ones were never probed. `not-attempted` had one
        # name and three causes, so a finding the budget dropped and one nothing
        # could ever test read alike. `no-tool-routed` is the one that indicts
        # the table rather than the budget — see `verification.NA_REASONS`.
        "not_attempted_by_reason": not_attempted,
        "dispatches_by_rule": per_rule,
        "tool_seconds": round(seconds, 2),
        "rounds_used": rounds_hist,
    }
    siblings = siblings or []
    if siblings:
        sib_outcome: dict[str, int] = {}
        for row in siblings:
            key = str(row.get("outcome") or "?")
            sib_outcome[key] = sib_outcome.get(key, 0) + 1
        summary["siblings"] = {
            # Everything the propagation dispatch considered, and — apart —
            # what it actually probed. A route the pre-check found unserved was
            # never a probe, and counting it as one would put a fact about a
            # constructed URL into a column about the application.
            "considered": len(siblings),
            "probed": sum(1 for r in siblings
                          if r.get("outcome") not in _SIBLING_UNPROBED),
            "routes_not_served": sum(
                1 for r in siblings
                if r.get("outcome") == verification.SIBLING_UNREACHABLE),
            # Served, and still not asked: a redirect or a server error means
            # the bytes the probe would judge belong to another page. Counted
            # apart from `routes_not_served` because that one is a verdict on
            # the claim's prediction and this one is a verdict on the probe.
            "routes_not_probeable": sum(
                1 for r in siblings
                if r.get("outcome") == verification.SIBLING_NOT_PROBEABLE),
            # What the constructed URLs actually answered. Worth a column of its
            # own because the pre-check exposed a SECOND weak-refutation class
            # the 404 rule does not catch: on the first run carrying it, all
            # seven served routes answered 302 — unauthenticated Gitea redirects
            # `/milestones` and `/pulls` to the login page, so those probes
            # tested the login page. The route exists, and it is still not the
            # page the claim meant.
            "by_route_status": {
                str(status): sum(1 for r in siblings
                                 if r.get("route_status") == status)
                for status in sorted(
                    {r.get("route_status") for r in siblings} - {None})
            },
            "claims": len({r.get("claim_id") for r in siblings}),
            "by_outcome": sib_outcome,
            # The headline number of the propagation half: routes ZAP never
            # flagged where an independent tool reproduced the weakness anyway.
            "confirmed_finding_ids": [r["finding_id"] for r in siblings
                                      if r.get("outcome") == CONFIRMED],
        }
    # Oracle-seeded marker probes, in their own block and never folded into
    # `by_outcome`: a ceiling reading aimed at a documented sink the scan never
    # flagged, with no ZAP alert behind it. Present only when the dispatch ran —
    # off, this key is absent and the summary is byte-identical to before.
    oracle_seeded = oracle_seeded or []
    if oracle_seeded:
        os_outcome: dict[str, int] = {}
        for row in oracle_seeded:
            key = str(row.get("outcome") or "?")
            os_outcome[key] = os_outcome.get(key, 0) + 1
        summary["oracle_seeded"] = {
            "markers_probed": len(oracle_seeded),
            "by_outcome": os_outcome,
            # The headline: documented CVE sinks confirmed by direct dispatch
            # because the in-band scanner's reach was budget-bound.
            "confirmed_finding_ids": [r["finding_id"] for r in oracle_seeded
                                      if r.get("outcome") == CONFIRMED],
        }
    if loop_info:
        agreement = loop_info.get("agreement") or {}
        # Records where BOTH readers spoke. A record the model never categorised
        # is not agreement — see `_count_agreement`.
        audited = sum(agreement.values())
        summary["loop"] = {
            "config": loop_info.get("config", {}),
            "findings_looped": loop_info.get("findings_looped", 0),
            "rounds_run": loop_info.get("rounds_run", 0),
            "tool_rounds": loop_info.get("tool_rounds", 0),
            "audited": audited,
            "agree": agreement.get(verification.AGREE, 0),
            "flagged": agreement.get(verification.FLAGGED, 0),
            # Per ROUND, not per finding: the declared signal is a
            # per-invocation pre-commitment, and a loop that declared one on its
            # first round and nothing on its correction has half a method.
            "signals": loop_info.get("signals") or {},
            # The classification-audit rate, over the records that HAVE two
            # readings. A fraction because the denominator moves with the
            # budget, and a bare count across two runs of different sizes is not
            # comparable. `None` — never 0.0 — when nothing was audited: a
            # measured zero disagreement and no measurement at all must not look
            # alike, which is the same rule the cost fields follow.
            "flagged_rate": (round(agreement.get(verification.FLAGGED, 0) / audited, 4)
                             if audited else None),
        }
    return summary


def build_artifact(source_name: str, run_id: str, budget: DispatchBudget,
                   verifications: list[dict[str, Any]],
                   correlated: list[dict[str, Any]],
                   per_rule: dict[str, int],
                   loop_info: "dict[str, Any] | None" = None,
                   oob: bool = False,
                   siblings: "list[dict[str, Any]] | None" = None,
                   table_version: "int | None" = None,
                   oracle_seeded: "list[dict[str, Any]] | None" = None) -> dict[str, Any]:
    siblings = siblings or []
    oracle_seeded = oracle_seeded or []
    summary = summarise(verifications, correlated, per_rule, loop_info, siblings,
                        oracle_seeded)
    artifact = {
        "schema_version": VERIFICATION_SCHEMA_VERSION,
        "run_id": run_id,
        "generated_at": run_paths.split_run_id(run_id)[0],
        "source_artifact": source_name,
        "vocabulary_version": verification.VERIFICATION_VOCAB_VERSION,
        # WHICH ROUTING PRODUCED THESE DISPATCHES — and it is the *correlation
        # artifact's* table version, not the live one, because that is where the
        # routing was actually decided. `verification.selected_tool` reads
        # `finding.deterministic.tool`, a value the table wrote at CORRELATE
        # time; editing a rule's `tool=` therefore changes nothing about a
        # stored corpus until `correlate` is re-run over it.
        #
        # Recording the live version here would therefore have stamped this
        # artifact "v4" over dispatches that v3 routed — a provenance field that
        # lies in exactly the case it exists for. → NEXT_SESSION §N3.
        "rescan_table_version": table_version,
        "budget": budget.as_dict(),
        "tools": {name: {"image": image} for name, image in TOOL_IMAGES.items()},
        # The configuration this run WAS, at the top of the artifact rather than
        # only on each record: the comparison this stage exists to support is
        # between runs, and a reader joining two artifacts should not have to
        # open a record to learn which configuration produced which.
        "config": (loop_info or {}).get("config", {}),
        # Whether out-of-band (OAST) templates were armed against the self-hosted
        # interactsh sink. Recorded because it changes what the run *could* have
        # found — two runs that differ here are not comparable on OOB classes.
        "oob_enabled": oob,
        # The loop's model/prompt/params, for rerun; None in the
        # fully-deterministic configuration, which calls no model.
        "loop": (loop_info or {}).get("metadata"),
        # Push (the default) or the model's own pulls from the context server —
        # two runs that differ here are not comparable on what the verifier saw.
        "retrieval": (loop_info or {}).get("retrieval"),
        "summary": summary,
        "verifications": verifications,
        "correlated_verifications": correlated,
        # The routes a propagation claim PREDICTED, probed at URLs built from
        # their templates. Their own section rather than mixed into
        # `verifications`: these carry no ZAP alert, their URLs were constructed
        # rather than observed, and a confirmation here is a finding the
        # deterministic pipeline could not have produced. Keeping them apart is
        # what lets the detection-rate accounting say which layer reached what.
        "sibling_verifications": siblings,
    }
    # Its own top-level array, and present ONLY when the dispatch ran: these
    # records carry no ZAP alert, their URL is the marker's documented sink, and a
    # confirmation here is a CEILING reading (VERIFY_ORACLE_SEED_DISPATCH), never a
    # blind detection — folding them into `verifications` would put a ceiling
    # number in the flagged population's column. Absent when off, so an off run's
    # artifact is byte-identical to one produced before this feature existed.
    if oracle_seeded:
        artifact["oracle_seeded_verifications"] = oracle_seeded
    return artifact


def print_summary(artifact: dict[str, Any]) -> None:
    """One section: what was selected on the left, what the tools returned on the
    right — the verify analogue of triage's in→out summary. The confirmed
    roster, the not-attempted reasons and the loop audit stay below it, since
    each changes how the counts above are read."""
    summary = artifact["summary"]
    by = summary["by_outcome"]
    left = [
        f"{summary['selected']} flagged + {summary['correlated_selected']} correlated",
        f"{summary['dispatched']} dispatched",
    ]
    right = [f"{by.get(o, 0)} {label}" for o, label in (
        (CONFIRMED, "confirmed"), (REFUTED, "refuted"),
        (INCONCLUSIVE, "inconclusive"), (NOT_ATTEMPTED, "not-attempted"))]

    phase = ui.open_phase("Verification summary")
    ui.two_columns("in", "out", left, right)
    for tool, counts in sorted(summary["by_tool"].items()):
        ui.item(f"  {tool}", " ".join(f"{k}={v}" for k, v in sorted(counts.items())))
    for row in artifact.get("verifications", []) + artifact.get(
            "correlated_verifications", []):
        if row.get("outcome") == CONFIRMED:
            # A reported confirmation is now always in-class: the class gate
            # requires a positive match, so mismatch/unknown/unspecific never
            # reach here — they are downgraded (handled below).
            ui.found(f"CONFIRMED `{row['finding_id']}` {row.get('rule_name', '')} "
                     f"via {row.get('tool')}: {row.get('evidence')}")
        elif row.get("outcome_downgraded_from") == CONFIRMED:
            # The wrapper reproduced something, but the class gate would not call
            # it a confirmation of THIS finding — a different class, a match too
            # unclassifiable to compare, or a rule whose own class cannot be
            # named. Confirmed by the tool, downgraded by the layer.
            check = row.get("classification") or {}
            ui.warn(f"downgraded confirmed→inconclusive `{row['finding_id']}` "
                    f"{row.get('rule_name', '')} via {row.get('tool')}: "
                    f"class check ({check.get('class')}) {check.get('detail')}")
    # Propagation siblings are their own population — routes a claim PREDICTS, at
    # URLs this pipeline built — so they are reported apart from the flagged set
    # rather than folded into `out`. Only shown when the propagation dispatch was
    # on (it is off by default); a confirmed sibling is the headline of the half.
    sib = summary.get("siblings") or {}
    if sib.get("considered"):
        confirmed = sib.get("confirmed_finding_ids") or []
        ui.item("propagation siblings",
                f"{sib['considered']} predicted · {sib['probed']} probed · "
                f"{len(confirmed)} confirmed "
                f"({sib['routes_not_served']} not served, "
                f"{sib['routes_not_probeable']} not probeable)")
        for fid in confirmed:
            ui.found(f"★ CONFIRMED sibling `{fid}` — a route ZAP never flagged, "
                     "reached only by the propagation claim")

    # Oracle-seeded marker probes, their own line for the same reason: a ceiling
    # reading (VERIFY_ORACLE_SEED_DISPATCH), only shown when the dispatch ran.
    oseed = summary.get("oracle_seeded") or {}
    if oseed.get("markers_probed"):
        confirmed = oseed.get("confirmed_finding_ids") or []
        ui.item("oracle-seeded dispatch",
                f"{oseed['markers_probed']} marker sink(s) probed · "
                f"{len(confirmed)} confirmed "
                f"(ceiling; VERIFY_ORACLE_SEED_DISPATCH)")
        for fid in confirmed:
            ui.found(f"★ ORACLE-SEEDED CONFIRMED `{fid}` — a documented CVE sink "
                     "confirmed by direct dispatch (no ZAP alert; a ceiling "
                     "reading, never a blind detection)")

    reasons = summary.get("not_attempted_by_reason") or {}
    if reasons:
        ui.item("not attempted, by reason", str(dict(sorted(reasons.items()))))
    unroutable = reasons.get(verification.NA_NO_TOOL, 0)
    if unroutable:
        # The number that indicts the table rather than the budget, said where the
        # numbers are read — a finding flagged on risk alone and routed nowhere is
        # exactly the shape of a missed detection.
        selected = summary["selected"] + summary["correlated_selected"]
        rules = sorted({str(r.get("plugin_id") or "?")
                        for r in artifact.get("verifications", [])
                        if r.get("not_attempted_reason") == verification.NA_NO_TOOL})
        ui.warn(
            f"{unroutable} of {selected} selected finding(s) were flagged for "
            "verification and NO ARM NAMED A TOOL for them, so nothing was "
            f"tested. Rule(s): {', '.join(rules[:12])}"
            + (f", … ({len(rules)} in total)" if len(rules) > 12 else "")
            + ". Each is a rule the rescan table does not route — the shape of "
              "the 40026 defect, where the corpus's only true positive was "
              "escalated on risk alone and dispatched nowhere."
        )
    if summary["dispatches_by_rule"]:
        # Each rule against the cap that actually governed IT — a rule named in
        # `max_dispatch_rule` has its own, and comparing every rule against the
        # blanket number would both miss a named rule at its own ceiling and
        # invent one for a rule held below it.
        budget_of = artifact["budget"]
        named = budget_of.get("max_dispatch_rule") or {}
        blanket = budget_of.get("max_dispatch_all_rules", verification.NO_CAP)
        capped = {}
        for rule, count in summary["dispatches_by_rule"].items():
            cap = named.get(rule, blanket)
            if cap != verification.NO_CAP and count >= cap:
                capped[rule] = f"{count}/{cap}"
        if capped:
            ui.warn(f"dispatch cap reached for plugin(s) {capped} — the "
                    "remaining findings on them are not-attempted, never refuted")
    loop = summary.get("loop")
    if loop:
        ui.item("tool rounds", f"{loop['tool_rounds']} invocation(s) over "
                               f"{loop['rounds_run']} loop round(s); rounds per "
                               f"finding {summary['rounds_used']}")
        invocation = (loop.get("config") or {}).get("invocation")
        if loop["audited"]:
            rate = f"{loop['flagged_rate']:.1%}"
            ui.item("wrapper vs model",
                    f"{loop['agree']} agree / {loop['flagged']} flagged ({rate}) "
                    f"over {loop['audited']} finding(s) with both readings")
        elif invocation == "deterministic":
            ui.item("wrapper vs model",
                    "no model reading — this is the fully-deterministic "
                    "configuration, the control the LLM ones are measured against")
        else:
            # invocation=llm, but nothing reached a two-reading comparison: the
            # model ran (it may have directed the probing) yet no finding
            # produced a model VERDICT to audit against the wrapper — e.g. the
            # only dispatch resolved on the tool's own reading. Labelling this
            # "fully-deterministic" would be wrong: the configuration called a
            # model (e.g. a lone dispatch a tool refuted without a model category).
            ui.item("wrapper vs model",
                    "model ran, but no finding produced a model verdict to "
                    "compare with the wrapper (nothing the model categorised "
                    "reached a two-reading comparison)")
        signals = loop.get("signals") or {}
        declared = sum(v for k, v in signals.items() if k != "not_declared")
        # All zeros in the deterministic configuration, where no round was
        # model-directed. Printing "0 declared / 0 not over 0 rounds" there
        # would be a line about a thing that did not happen.
        if sum(signals.values()):
            ui.item("declared signals",
                    f"{declared} declared / {signals.get('not_declared', 0)} not, "
                    f"over {sum(signals.values())} round(s) — "
                    f"matched {signals.get('matched', 0)}, "
                    f"absent {signals.get('absent', 0)}, "
                    f"contradiction {signals.get('contradiction', 0)}, "
                    f"not checkable {signals.get('not_checkable', 0)}")
        # A declaration nothing could be tested against is not a prediction that
        # failed — see `verification.check_signal`. Said out loud because the
        # rounds still count as "declared" above, and on this corpus they are
        # the majority: 535 of 868 in the sheet-10 runs.
        if signals.get("not_checkable"):
            ui.warn(
                f"{signals['not_checkable']} of {declared} declared signal(s) "
                "could not be checked at all: the probe never ran, the tool "
                "reported no observation to search, or every string named was "
                "already in the invocation sent. Those rounds falsified "
                "nothing, in either direction."
            )
        if signals.get("not_declared") and declared == 0 and loop["audited"]:
            # Loud, because it is invisible in the verdicts: every outcome still
            # looks fine while the falsifiable half of the method is gone. That
            # is exactly how it was lost once — dropped from the response
            # schema's `required` list in a refactor.
            ui.warn(
                "NOT ONE round declared a checkable signal. The verdicts below "
                "stand on the tools' own output alone; the pre-commitment that "
                "makes a round falsifiable is missing. Check that "
                "`declared_signal` is still required in verify_loop.ROUND_SCHEMA."
            )
        if loop["flagged"]:
            # Not a warning: a disagreement is the measurement, not a fault. But
            # it is the thing a reader should look at, so it is named rather
            # than left to be found in a 3000-line artifact.
            ui.item("  flagged findings",
                    ", ".join(r["finding_id"] for r in
                              artifact.get("verifications", [])
                              + artifact.get("correlated_verifications", [])
                              if r.get("agreement") == verification.FLAGGED)[:200])
    phase.close(timed=False)


def print_model_usage(loop_info: dict[str, Any]) -> None:
    """What the verification loop's model calls cost — the verify analogue of
    triage's ``print_model_usage``.

    The spend was always in ``verify-metrics.json`` (``cost_usd`` and the
    token counts), but nowhere in the feed: a stage that spends the key should
    say so while it runs, exactly as triage does, so "what does verification cost
    in CI" is answerable from the log and not only the artifact. Nothing prints
    in the fully-deterministic configuration, which calls no model.
    """
    meta = loop_info.get("metadata") or {}
    usage = meta.get("usage") or {}
    if not usage:
        return
    phase = ui.open_phase("Model usage — verification loop")
    ui.item("model", meta.get("model") or "?")
    ui.item("calls", int(usage.get("calls", 0) or 0))
    ui.item("tokens", f"{int(usage.get('prompt_tokens', 0) or 0)} prompt + "
                      f"{int(usage.get('completion_tokens', 0) or 0)} completion")
    if usage.get("cached_prompt_tokens"):
        ui.item("cached prompt tokens", int(usage["cached_prompt_tokens"]))
    ui.item("cost", f"${float(usage.get('cost_usd', 0) or 0):.4f}")
    if usage.get("failed_calls") or usage.get("retried_calls"):
        ui.item("failed / retried",
                f"{int(usage.get('failed_calls', 0) or 0)} / "
                f"{int(usage.get('retried_calls', 0) or 0)}")
    phase.close(timed=False)


# -- the evidence the loop reasons from ------------------------------------


def build_contexts(layout: run_paths.RunLayout, correlation: dict[str, Any],
                   findings: list[dict[str, Any]],
                   target: Any) -> dict[str, dict[str, Any]]:
    """The HTTP exchange and the handler source behind each selected finding.

    Both are read off the run's own artifacts, with the *same* machinery triage
    used — the message sidecar and the ctags symbol index over Noir's scope —
    rather than re-derived here. What is deliberately not read is anything
    triage *concluded*: see :func:`dast_orchestrator.analysis.verify_loop.build_context`.

    The code level is taken from the correlation artifact's own provenance, so a
    verification of a run triaged without code context does not silently reason
    from source triage never saw, and one of a ``handler+trace`` run gets the same
    blocks. A run that cannot resolve source degrades to no source block, which
    the task states explicitly rather than leaving the model to assume an empty
    handler.
    """
    from dast_orchestrator.context import evidence

    contexts: dict[str, dict[str, Any]] = {
        f["finding_id"]: {} for f in findings
    }
    for finding_id, exchange in _load_exchanges(layout, findings).items():
        contexts[finding_id]["exchange"] = exchange

    provenance = correlation.get("evidence") or _evidence_from_metrics(layout)
    code_level = str(provenance.get("code_context_level") or "none")
    if code_level == "none":
        return contexts
    try:
        run = join.load_run(layout.data_dir, layout.run_id)
    except JoinError as exc:
        ui.warn(f"no scan artifacts to resolve handler source from ({exc}) — "
                "the loop runs without it.")
        return contexts

    assembler = evidence.assembler_for_run(
        run.zap_report, layout.path(run_paths.ZAP_MESSAGES),
        code_level=code_level, target=target,
        # The same tree triage resolved, through the one configurable reader —
        # so the loop reads the source at wherever the targets dir points.
        source_dir=targets.target_source(target) if target.source_dir else None,
        max_hops=int(provenance.get("code_context_max_hops") or 1),
        max_lines=int(provenance.get("code_context_max_lines") or 600),
    )
    if not assembler.code_enabled:
        return contexts
    bundles = join.build_bundles(run)
    assembler.prepare(bundles)
    by_key = {b.identifier: b for b in bundles}
    with_noir = located = 0
    for finding in findings:
        bundle = by_key.get(str(finding.get("endpoint_key") or "")) or by_key.get(
            f"{finding.get('method')} {finding.get('path')}")
        if bundle is None:
            continue
        if bundle.has_static_context:
            with_noir += 1
        located += assembler.grounding([bundle])["handler_located"]
        source = assembler.endpoint_context(bundle)
        if source:
            contexts[finding["finding_id"]]["source"] = source
    # Same "code context" line triage prints, in the same vocabulary: the level,
    # the hop budget, and the resolution counts (Noir's ai-context, the
    # ctags-resolved source, and how much of that is the endpoint's own handler).
    # Counted per finding here — the unit this stage works in — where triage
    # counts per candidate endpoint.
    n = len(findings)
    hops = assembler.max_hops
    with_source = count_grounded(contexts)
    ui.item("code context",
            f"{code_level} - {hops} hop{'s' if hops != 1 else ''}"
            f" - {with_noir}/{n} noir resolved - {with_source}/{n} ctag resolved"
            f" - {located}/{n} handler located")
    return contexts


def count_grounded(contexts: dict[str, dict[str, Any]]) -> int:
    """How many of these contexts actually carry handler source.

    A context block is attached to **every** endpoint, including one whose
    symbols the index could not resolve — it then holds an empty ``blocks`` list
    and a ``note`` saying no source is attached, which is honest to the model
    and is not source. Counting the blocks rather than the source *in* them
    over-reports grounding — an empty-``blocks`` finding counts as grounded when
    its true source figure is 0.

    The bug is invisible on the target where grounding works — Gitea read
    "36 of 36" and that was true — which is why it survived, and why this is a
    named function with a test rather than a `sum` in a log line. The number is
    what a reader uses to judge whether a verification result was
    source-grounded at all.
    """
    return sum(1 for c in contexts.values()
               if (c.get("source") or {}).get("blocks"))


def _evidence_from_metrics(layout: run_paths.RunLayout) -> dict[str, Any]:
    """The triage stage's evidence settings, for a correlation written before
    the artifact carried them.

    Older correlations record the code level only in ``triage-metrics.json``.
    Reading it there keeps every stored corpus verifiable at the level it was
    triaged at, instead of silently degrading a
    ``handler+trace`` run to no source — which would look like the loop reasoning
    from nothing and read as a property of the loop rather than of the artifact.
    """
    for record in run_metrics.read_run_records(layout.data_dir, layout.run_id):
        if record.get("kind") != "triage":
            continue
        config = record.get("config") or {}
        if config.get("code_context"):
            return {
                "code_context_level": config["code_context"],
                "code_context_max_hops": config.get("code_context_hops"),
                "code_context_max_lines": config.get("code_context_lines"),
            }
    return {}


# -- dry run ---------------------------------------------------------------



def _load_exchanges(layout: run_paths.RunLayout,
                    findings: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """The HTTP exchange behind each finding, for the model-directed rescan task.

    Read from the gitignored ``scan-zap-messages.json`` sidecar the scan wrote. An
    absent sidecar (a run from before the message layer) yields an empty map —
    the task then simply carries no exchange, exactly as the assembler degrades.
    """
    from dast_orchestrator.context import evidence
    store = evidence.MessageStore.load(layout.path(run_paths.ZAP_MESSAGES))
    if not len(store):
        return {}
    # Verification's question is often literally "is the flagged value reflected
    # in the body" — an XSS sink, a redirect target — so the excerpt is centred
    # on where the payload landed, not the first N characters: a head-only excerpt
    # leaves the model unable to see whether the value is reflected into the body.
    # `around-match` windows on
    # the flagged value and falls back to `head` when it is absent, and the
    # budget is larger because a verification runs one finding at a time — the
    # per-endpoint economy that keeps a whole-corpus triage prompt small does
    # not apply here.
    rule = evidence.ExcerptRule(body="around-match", body_chars=4000)
    out: dict[str, dict[str, Any]] = {}
    for finding in findings:
        alert = finding.get("alert") or {}
        exchange = store.exchange(alert.get("message_ids") or [])
        if exchange is not None:
            # The needles the window centres on: what ZAP saw, the payload it
            # sent, and the flagged parameter name — any of which locates the
            # region a verifier has to read.
            needles = [alert.get("evidence") or "", alert.get("attack") or "",
                       alert.get("param") or ""]
            out[finding["finding_id"]] = evidence.excerpt_exchange(
                exchange, rule, needles)
    return out


__all__ = [
    '_REFUSAL_DETAIL',
    '_refusal_detail',
    'directed_arguments',
    '_synthesis_not_attempted_detail',
    '_synthesis_not_attempted_code',
    'loop_config',
    'run_loop',
    '_round_record',
    'verify_all',
    '_can_dispatch',
    '_add_signals',
    '_tool_rounds',
    '_count_agreement',
    '_renamed',
    '_record',
    '_correlated_record',
    '_SIBLING_BLOCKED_DETAIL',
    '_SIBLING_UNPROBED',
    '_sibling_line',
    '_BAR',
    '_loop_warn',
    '_verdict_line',
    'select_findings',
    'summarise',
    'build_artifact',
    'print_summary',
    'print_model_usage',
    'build_contexts',
    'count_grounded',
    '_evidence_from_metrics',
    '_load_exchanges',
]
