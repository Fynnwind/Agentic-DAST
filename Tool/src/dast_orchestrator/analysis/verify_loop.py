"""The verification loop: one loop per finding, up to
:data:`~dast_orchestrator.domain.verification.DEFAULT_MAX_ROUNDS` rounds of propose →
react → refine, each round feeding the tool's raw output back to the model.

Two load-bearing invariants: the loop is given the handler source but NOT what triage
concluded (anti-circularity, so "verification agrees with triage" cannot be circular),
and each round the wrapper also classifies the output with fixed rules so
:func:`~dast_orchestrator.domain.verification.resolve_verdict` decides what is reported.
→ DECISIONS.md.
"""

from __future__ import annotations

import json
from typing import Any

from dast_orchestrator.analysis import screening
from dast_orchestrator.foundation import prompts
from dast_orchestrator.domain import verification
from dast_orchestrator.domain.verification import (
    INCONCLUSIVE,
    NOT_ATTEMPTED,
    LoopVerdict,
    RoundRecord,
)

#: Tool-reasoning workload — read a finding and its handler source, choose an
#: invocation, declare a signal, then read a security tool's raw output — so the
#: default comes from the agentic/tool-use family rather than the cheapest tier.
#:
#: **This id is pinned, despite carrying no date.** In the OpenRouter catalogue
#: `minimax/minimax-m2.5` is its own entry and coexists with `minimax-m2.7` and
#: `minimax-m3` as *separate ids*: a version bump mints a new id rather than being
#: served in place of the old one, and no dated snapshot of m2.5 exists to pin to —
#: the version tag is the finest granularity offered.
#: The genuinely floating ids are distinguishable by shape and are the ones to
#: refuse: a `~` prefix (`~deepseek/deepseek-v4-flash-latest`) or a bare family
#: name with no version at all (`deepseek/deepseek-v4-flash`,
#: `minimax/minimax-m2`). Override with ``--model`` / ``VERIFY_MODEL``.
VERIFY_MODEL = "minimax/minimax-m2.5"

#: Completion ceiling for one round. Higher than the triage default because this
#: family reasons at length before answering and a round cannot be split to fit —
#: it is one finding, and a lower ceiling truncated real sqlmap proposals.
ROUND_MAX_TOKENS = 24576

#: Ceiling on findings put through the loop in one run, on top of the dispatch
#: budget. The budget bounds *tool* calls; this bounds *model* calls, and the
#: two are spent by different things — a run where every loop concludes at round
#: one costs the same tools and a third of the tokens.
MAX_LOOPED_FINDINGS = 40

#: Structured-output contract for one round. ``additionalProperties: false``
#: keeps strict providers honest; the code still validates the invocation
#: (:func:`~dast_orchestrator.domain.verification.validate_probe`) and resolves the
#: category through the matrix rather than trusting either — the model proposes,
#: the executor disposes.
ROUND_SCHEMA: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "action": {
            "type": "string",
            "enum": ["continue", "conclude"],
            "description": "continue: run another, DIFFERENT invocation. "
                           "conclude: settle it with `category`.",
        },
        "category": {
            "type": "string",
            "enum": list(verification.LLM_CATEGORIES),
            "description": "Required for action=conclude. A 'refuted' means the "
                           "tool did the work and found nothing.",
        },
        # Derived, never listed by hand: a tool the driver can dispatch and the
        # capability block describes, but which the schema omits, is one the
        # model is told about and then forbidden to choose — structured output
        # rejects the value. `browser` was exactly that when it first arrived, so
        # the full-llm configuration could read what an execution oracle does and
        # never ask for one.
        "tool": {"type": "string",
                 "enum": sorted(verification.DISPATCHABLE_TOOLS)},
        "arguments": {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "param": {"type": "string",
                          "description": "Parameter to attack, or '' to keep the flagged one."},
                "method": {"type": "string",
                           "description": "HTTP method, or '' to keep the original."},
                "data": {"type": "string",
                         "description": "POST/PUT body a=1&b=2, or '' for none."},
                "tags": {"type": "string",
                         "description": "nuclei template tags to narrow the run, or ''."},
                "level": {"type": "integer", "description": "sqlmap breadth 1-5."},
                "risk": {"type": "integer", "description": "sqlmap risk 1-3."},
                "path_injection": {
                    "type": "boolean",
                    "description": "True when the injectable position is a URL "
                                   "PATH SEGMENT rather than a named parameter. "
                                   "The executor then places sqlmap's `*` "
                                   "marker in the path for you; leave `param` "
                                   "empty."},
            },
        },
        "declared_signal": {
            "type": "object",
            "additionalProperties": False,
            "description": "The observable that means the finding is real, "
                           "committed to before this round's tool runs.",
            "properties": {
                "expect": {"type": "array", "items": {"type": "string"},
                           "description": "Substrings that must appear if real."},
                "reject": {"type": "array", "items": {"type": "string"},
                           "description": "Substrings that must NOT appear."},
                "require_tool_confirmed": {
                    "type": "boolean",
                    "description": "True when the tool's own confirmed finding is the signal."},
                "description": {"type": "string"},
            },
        },
        "reasoning": {"type": "string"},
        "note": {"type": "string",
                 "description": "What the previous round's output showed, and "
                                "what this round changes. Empty on round 1."},
    },
    # `declared_signal` is REQUIRED, and that is load-bearing rather than
    # tidiness. The pre-commitment — stating what would be observed if the
    # finding were real, before the tool runs — is this stage's novel
    # methodological contribution, and it is the only thing that makes a round
    # falsifiable rather than a narration of whatever came back. The first live
    # run of this loop declared NO signal on a single round, because the
    # rebuild dropped it from `required` where the schema it replaced had it:
    # left optional, the model simply omits it, and the loss is silent.
    "required": ["action", "tool", "declared_signal", "reasoning"],
}


# -- the evidence the loop reasons from ------------------------------------


def build_context(finding: dict[str, Any],
                  exchange: "dict[str, Any] | None" = None,
                  source: "dict[str, Any] | None" = None,
                  fixed_tool: "str | None" = None,
                  max_rounds: int = verification.DEFAULT_MAX_ROUNDS,
                  oracle: "dict[str, Any] | None" = None,
                  earlier_triage: "dict[str, Any] | None" = None) -> dict[str, Any]:
    """The task handed to the model for one finding, on round 1.

    Carries what an independent check needs and nothing that would prejudge it:
    the finding and ZAP's own observation, the HTTP exchange when the sidecar
    holds one, **the handler source**, and the capabilities of every tool that
    could be dispatched.

    What it deliberately does *not* carry is any triage conclusion — no verdict,
    no reasoning, no suggested tool. See the module docstring: an independent
    check that is handed the hypothesis it is meant to test is not one.

    **Oracle-guided (``--ceiling``) runs are the one exception, and they buy the
    ceiling by giving that up.** There the task carries ``earlier_triage``: what
    pass 1 concluded about this finding, including whether it judged the alert
    to be the one a documented weakness would raise. That is deliberate — the
    mode asks how much this pipeline can confirm when nothing is withheld from
    it, and a security engineer holding the advisory would read the triage notes
    too. It also means a ceiling run's verification is **not independent of its
    own triage**, which is a further reason its numbers can never sit beside a
    blind run's. The exception is keyed on the oracle block being present, so it
    cannot leak into a blind run.

    :param source: the endpoint's ``handler_source`` block, exactly as the
        assembler builds it for triage. ``None`` when the run has no code
        context (no source tree, no index, or ``TRIAGE_CODE_CONTEXT=none``) — the task
        then says so rather than silently reading as though the handler were
        empty.
    :param earlier_triage: :func:`triage_view` of this finding. **Ignored unless
        ``oracle`` is set** — belt and braces on the invariant above, so a caller
        that passes one by mistake cannot make a blind run circular.
    :param fixed_tool: the tool the deterministic lookup chose for this finding.
        Told to the model so it directs an invocation for the tool that will
        actually run, rather than proposing one for a tool it will not get.
    :param oracle: the target's documented vulnerabilities, in oracle-guided
        (``--ceiling``) runs only — see :mod:`dast_orchestrator.analysis.oracle`.

        Note what this does **not** relax. Knowing a bug is documented changes
        where the probe is aimed; it never changes what the tool's output says,
        and :func:`~dast_orchestrator.domain.verification.resolve_verdict` still
        refuses a ``confirmed`` the tool's own machinery did not report. The
        anti-circularity rule is also untouched: this is a fact about the
        *application*, published in an advisory, not a conclusion this run's
        triage reached — which is the thing the loop must never be handed.
    """
    alert = finding.get("alert") or {}
    task: dict[str, Any] = {
        **({"known_vulnerabilities_of_this_target": oracle} if oracle else {}),
        # Keyed on `oracle`, never on `earlier_triage` alone: a caller that
        # passes a triage view by mistake cannot make a blind run circular.
        **({"earlier_triage": earlier_triage} if oracle and earlier_triage else {}),
        "finding": {
            "finding_id": finding.get("finding_id"),
            "zap_rule": alert.get("name"),
            "plugin_id": alert.get("plugin_id"),
            "risk": alert.get("risk"),
            "zap_confidence": alert.get("confidence"),
            "flagged_parameter": alert.get("param"),
            "what_zap_observed": alert.get("evidence") or alert.get("attack") or "",
            "rule_description": alert.get("description") or "",
            "example_url": (alert.get("example_urls") or [""])[0],
            "method": alert.get("method") or finding.get("method") or "GET",
            "route": finding.get("path") or finding.get("endpoint_key") or "",
        },
        "verification_tools": verification.tool_capabilities(
            sorted(verification.DISPATCHABLE_TOOLS)),
        "loop": {
            "max_rounds": max_rounds,
            "note": "You may run up to max_rounds invocations. On the final "
                    "round you must conclude.",
        },
    }
    if fixed_tool:
        task["tool_is_fixed"] = {
            "tool": fixed_tool,
            "why": "A deterministic lookup keyed on the ZAP rule already chose "
                   "this tool for this finding. Direct its invocation; do not "
                   "propose a different tool.",
        }
    if exchange is not None:
        task["http_exchange"] = exchange
    task["handler_source"] = source if source is not None else {
        "note": "No handler source is available for this endpoint in this run — "
                "the target declares no source scope, the tree is absent, or "
                "this run was configured without code context. Reason from "
                "ZAP's observation and the HTTP exchange alone, and do not "
                "assume anything about the handler you cannot see."
    }
    return task


def triage_view(finding: dict[str, Any]) -> "dict[str, Any] | None":
    """What pass 1 concluded about this finding, for an oracle-guided run only.

    Deliberately the *whole* judgement — both arms' rescan flags, the model's
    verdict and its reasoning — because the point in ceiling mode is that
    nothing is withheld. ``None`` when neither arm said anything, so an
    unevaluated finding does not arrive carrying an empty block that would read
    like a clean bill of health.

    Never reached outside ``--ceiling``: :func:`build_context` drops it unless
    the oracle block is present. See that function for why the blind loop must
    not see any of it.
    """
    llm = finding.get("llm") or {}
    det = finding.get("deterministic") or {}
    if not llm and not det:
        return None
    view: dict[str, Any] = {
        "note": "What THIS pipeline's triage stage concluded about this finding. "
                "You are shown it because this is an oracle-guided ceiling run; "
                "a blind run withholds it so that this check stays independent.",
        "deterministic_flagged_for_rescan": bool(det.get("needs_rescan")),
    }
    if llm:
        view["pass1_verdict"] = llm.get("verdict")
        view["pass1_wants_rescan"] = llm.get("needs_rescan")
        view["pass1_reasoning"] = llm.get("reasoning")
        view["pass1_suggested_tool"] = llm.get("suggested_tool")
    elif finding.get("llm_asked"):
        # Asked and unanswered is missing information, never a clean result —
        # the same distinction the correlation artifact draws.
        view["pass1_verdict"] = "asked-but-unanswered"
    return view


def build_messages(context: dict[str, Any],
                   system_prompt: "str | None" = None) -> list[dict[str, Any]]:
    """The opening conversation for a loop. Later rounds append to it.

    Two messages, and the split is what makes prompt caching pay: the system
    prompt and this task block are re-sent verbatim on every round, so they are
    a stable prefix, while only the newest tool output is new. See
    :meth:`~dast_orchestrator.analysis.screening.OpenRouterCorrelator.complete`.
    """
    return [
        {"role": "system",
         "content": system_prompt or prompts.load("verify").text},
        {"role": "user", "content": json.dumps(context, indent=1)},
    ]


def round_result_message(record: RoundRecord, rounds_left: int) -> dict[str, str]:
    """The tool's actual output, handed back for the next round.

    Deliberately the wrapper's *whole* verdict — its outcome, its own words, the
    command that produced it, the exit code, its own scan counters and the
    stdout excerpt — rather than a summary. The point of looping at all is that the model reacts to what the
    tool really said; a paraphrase would put this module's reading of the output
    between the tool and the model, which is the lossy channel the redesign
    removed on the triage side.
    """
    result = record.tool_result or {}
    payload = {
        "round": record.index,
        "you_ran": {"tool": record.tool, "arguments": record.arguments or {}},
        "your_declared_signal": record.declared_signal or {},
        "signal_check": record.signal_check or {},
        "tool_output": {
            "outcome": result.get("outcome"),
            "detail": result.get("detail"),
            "evidence": result.get("evidence"),
            "command": result.get("command"),
            "exit_code": result.get("exit_code"),
            "timed_out": result.get("timed_out"),
            "tool_warnings": result.get("tool_warnings") or [],
            # What the tool actually did, when it counts itself. Without this a
            # nuclei run that matched nothing reaches the model as an EMPTY
            # stdout plus this pipeline's own word "refuted" — all the evidence it
            # had when it once agreed to refute a live XSS. A stats object like
            # `{"templates": 195, "requests": 387, "matched": 0}` is a fact the
            # model can weigh; an empty string is not.
            "scan_stats": result.get("scan_stats"),
            "stdout_excerpt": (result.get("stdout_excerpt") or "")[:1500],
            "stderr_excerpt": (result.get("stderr_excerpt") or "")[:600],
        },
        "rounds_left": rounds_left,
    }
    tail = ("This was the last round — you must conclude now."
            if rounds_left <= 0 else
            "Conclude, or continue with a different invocation.")
    return {"role": "user", "content": json.dumps(payload, indent=1) + "\n\n" + tail}


# -- normalising one round's proposal --------------------------------------


def normalise_round(raw: dict[str, Any], fixed_tool: "str | None" = None,
                    last_round: bool = False) -> dict[str, Any]:
    """Coerce a raw model round into a safe, executable shape.

    Three things are enforced here rather than trusted to the schema:

    * the invocation goes through
      :func:`~dast_orchestrator.domain.verification.validate_probe`, which drops the
      target, the timeout and anything else the model may not set;
    * a ``continue`` on the last round is marked ``forced``: its probe still
      runs — the model asked for one more and there is exactly one round left to
      run it in — but the loop then ends at the cap with **no model category**,
      because the model never gave one. Inventing an ``inconclusive`` on its
      behalf would put a judgement it did not make into the agreement counts;
    * a ``conclude`` with no usable category becomes ``inconclusive`` — the
      state that claims nothing.
    """
    action = raw.get("action")
    if action not in ("continue", "conclude"):
        action = "conclude"
    forced = last_round and action == "continue"
    category = raw.get("category")
    if action == "conclude" and category not in verification.LLM_CATEGORIES:
        category = INCONCLUSIVE
    if action == "continue":
        category = None

    tool = fixed_tool or raw.get("tool")
    signal = verification.DeclaredSignal.from_dict(raw.get("declared_signal"))
    out: dict[str, Any] = {
        "action": action,
        "forced": forced,
        "category": category,
        "signal": signal.as_dict(),
        "signal_declared": not signal.is_empty,
        "reasoning": str(raw.get("reasoning") or "").strip(),
        "note": str(raw.get("note") or "").strip(),
    }
    if tool not in verification.DISPATCHABLE_TOOLS:
        out.update({"tool": None, "arguments": {},
                    "violations": [f"unknown tool {tool!r}"], "executable": False})
        return out
    args, violations = verification.validate_probe(tool, raw.get("arguments"))
    if fixed_tool and raw.get("tool") not in (None, "", fixed_tool):
        violations = [*violations,
                      f"ignored proposed tool {raw.get('tool')!r}: the "
                      f"deterministic lookup fixed this finding to {fixed_tool}"]
    out.update({"tool": tool, "arguments": args, "violations": violations,
                "executable": True})
    return out


# -- what a loop that never got going records ------------------------------


def unattempted(finding_id: str, reason: str,
                wrapper_outcome: str = NOT_ATTEMPTED,
                code: str = "") -> LoopVerdict:
    """A finding the loop could not start on, recorded rather than dropped.

    A refusal (no dispatchable tool, no probeable URL), a budget that bit first,
    or a model that never answered. All are ``not-attempted``, and the reason is
    kept: "we did not check" and "we checked and it was clean" must never look
    alike, and neither must the several distinct reasons for the first.

    :param code: one of :data:`verification.NA_REASONS`, so the distinct reasons
        are countable and not only readable. ``reason`` stays the prose; this is
        the same fact in a form a summary can total, which is what it took to
        notice that 200 of 283 flagged findings on one corpus were routed
        nowhere at all.
    """
    return LoopVerdict(
        finding_id=finding_id,
        reported=wrapper_outcome,
        wrapper_verdict=wrapper_outcome,
        llm_verdict=None,
        agreement=verification.AGREE,
        rounds=(),
        tool=None,
        detail=reason,
        stopped_because=reason,
        not_attempted_reason=code,
    )


def settle(finding_id: str, rounds: list[RoundRecord],
           llm_category: "str | None", stopped_because: str,
           alert: "dict[str, Any] | None" = None) -> LoopVerdict:
    """Resolve a finished loop's two readings into the one reported verdict.

    The finding's deterministic verdict is the wrapper's reading of the **last
    round that actually dispatched a tool**, which is the round the model
    concluded from — comparing the model's category against a different round's
    output would audit nothing.

    "Last round that dispatched" rather than plainly "last round", because a
    budget can refuse a round after earlier ones have already produced evidence.
    Taking that refusal as the verdict would report ``not-attempted`` for a
    finding a tool had in fact tested and refuted one round earlier — throwing
    away real work and, worse, recording "we did not check" for something that
    was checked. Every round's reading is kept in the trace either way, so the
    trajectory stays visible.

    When ``alert`` is given, a ``confirmed`` is additionally gated on CLASS
    agreement here, where the verdict is formed — a tool match confirms this
    finding only if it is in the flagged rule's class
    (:func:`...verification.class_gate`). This is the one place the class
    constraint applies, not a downstream patch on the finished record, and the
    wrapper's own reading is kept in ``wrapper_verdict`` either way.
    """
    dispatched = [r for r in rounds if r.wrapper_outcome != NOT_ATTEMPTED]
    if not dispatched:
        return unattempted(finding_id, stopped_because or "no round ran")
    final = dispatched[-1]
    rounds = list(rounds)
    reported, agreement = verification.resolve_verdict(
        final.wrapper_outcome, llm_category, final.tool_ran)
    detail = (final.tool_result or {}).get("detail", "")
    classification = None
    downgraded_from = None
    if alert is not None and reported == verification.CONFIRMED:
        reported, extra = verification.class_gate(
            reported, alert.get("cweid"),
            (final.tool_result or {}).get("matched_templates"),
            rule_id=str(alert.get("plugin_id") or ""), tool=final.tool)
        classification = extra.get("classification")
        downgraded_from = extra.get("outcome_downgraded_from")
    if agreement == verification.FLAGGED:
        detail = (f"wrapper read {final.wrapper_outcome!r}, model read "
                  f"{llm_category!r} — reported {reported!r}. {detail}").strip()
    if downgraded_from:
        detail = (f"{detail}  [class gate: {classification['detail']}]").strip()
    return LoopVerdict(
        finding_id=finding_id,
        reported=reported,
        wrapper_verdict=final.wrapper_outcome,
        llm_verdict=llm_category,
        agreement=agreement,
        rounds=tuple(rounds),
        tool=final.tool,
        detail=detail,
        stopped_because=stopped_because,
        classification=classification,
        outcome_downgraded_from=downgraded_from,
    )


# -- run metadata ----------------------------------------------------------


def run_metadata(model: str, usage: Any, config: dict[str, Any],
                 looped: int, rounds_run: int, agreement: dict[str, int],
                 prompt: "prompts.Prompt | None" = None,
                 capabilities: "dict[str, Any] | None" = None) -> dict[str, Any]:
    """The ``loop`` block of the verification artifact — enough to rerun it.

    :param capabilities: what the served model advertises (the client's resolved
        :func:`screening.model_capabilities`), so the record says whether the
        requested ``temperature``/``seed`` below could actually be honoured —
        the same distinction the triage artifact records. ``None`` means unknown.
    """
    prompt = prompt or prompts.load("verify")
    return {
        "model": model,
        "temperature": screening.TEMPERATURE,
        "seed": screening.SEED,
        # Requested above; whether the model accepts them, so a seed in the
        # artifact is never read as determinism the run did not have.
        "model_capabilities": capabilities,
        "seed_supported": (None if capabilities is None
                           else capabilities.get("seed")),
        "temperature_supported": (None if capabilities is None
                                  else capabilities.get("temperature")),
        **prompt.as_metadata(),
        "response_schema": ROUND_SCHEMA,
        "config": config,
        "findings_looped": looped,
        "rounds_run": rounds_run,
        "agreement": agreement,
        "usage": usage.as_dict() if usage is not None else None,
    }


#: The counters a loop run reports. ``flagged`` is the classification-audit
#: disagreement rate and the number this redesign exists to produce: how often
#: the wrapper's fixed rules and the model's reading of the *same* tool output
#: differ. It is obtained for free, on the model's own calls.
def empty_agreement() -> dict[str, int]:
    return {verification.AGREE: 0, verification.FLAGGED: 0}


def signal_counts(rounds: "list[RoundRecord]") -> dict[str, int]:
    """How each round's declared signal related to the tool's own verdict.

    * ``matched`` — the signal appeared and the tool confirmed: the model
      predicted right.
    * ``absent`` — the signal did not appear on a refutation: consistent, there
      was nothing there.
    * ``contradiction`` — the tool refuted but the declared signal DID appear.
      The chain-of-verification catch, and the one a human should read.
    * ``not_declared`` — the model committed to nothing checkable. Counted and
      reported rather than tolerated: a run where this dominates has lost the
      falsifiable half of the method while still producing verdicts that look
      fine.
    * ``not_checkable`` — it declared something and nothing could be tested
      against it: the probe never ran, the tool reported no observation, or
      every string it named was already in the invocation the executor sent.
      Its own code because a budget-refused round produces no output whatsoever,
      and filing that under ``absent`` would read as a prediction checked and failed.

    Only rounds a model actually directed are counted — see
    :attr:`~dast_orchestrator.domain.verification.RoundRecord.model_directed`.
    """
    counts = {"matched": 0, "absent": 0, "contradiction": 0,
              "not_declared": 0, "not_checkable": 0}
    for record in rounds:
        if not record.model_directed:
            # A deterministic probe makes no prediction because nothing was
            # asked to make one. Counting it as an undeclared signal would put
            # the fully-deterministic control's 34 rounds into the column that
            # measures whether the MODEL is committing to anything.
            continue
        check = record.signal_check or {}
        observed = check.get("observed")
        # `code` is authoritative; `observed is None` is the fallback for a
        # record written before the two None cases were told apart.
        code = check.get("code") or (
            verification.SIGNAL_NOT_DECLARED if observed is None
            else verification.SIGNAL_OBSERVED if observed
            else verification.SIGNAL_ABSENT)
        if code == verification.SIGNAL_NOT_DECLARED:
            counts["not_declared"] += 1
        elif code == verification.SIGNAL_NOT_CHECKABLE:
            counts["not_checkable"] += 1
        elif observed and record.wrapper_outcome == verification.REFUTED:
            counts["contradiction"] += 1
        elif observed:
            counts["matched"] += 1
        else:
            counts["absent"] += 1
    return counts
