"""The round-loop contract: the declared-signal check, the det × llm ``resolve_verdict``,
per-round and whole-loop records, and the sibling population's routing.

Part of the ``verification`` package (with ``outcomes`` and ``dispatch``); the package
``__init__`` re-exports every name, so ``verification.X`` is unchanged.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from dast_orchestrator.domain.verification.outcomes import *  # shared vocabulary  # noqa: F401,F403




# -- model-directed verification: the executor's contract ------------------
#
# The model proposes the invocation AND the signal it expects; a deterministic
# executor validates and runs it (deterministic dispatch stays as the control arm).
# - Command authority is over HOW a finding is probed, never WHERE: the executor
#   derives the target, so the model cannot aim a tool at an unasked host.
# - The declared signal: the model commits, BEFORE the tool runs, to the observable
#   that would mean the finding is real, so its reading is checkable rather than an
#   unfalsifiable after-the-fact call.
# → DECISIONS.md.

#: Probe-argument keys the model may set. It directs HOW a finding is probed
#: (parameter, method, body, template tags, sqlmap breadth) — never the target URL
#: (the executor derives it, so the model cannot aim a tool at an unasked host) and
#: never the timeout (the budget owns it). ``path_injection`` is the model's way to
#: say the injectable position is a URL path segment, not a named parameter: it sets
#: no target, only asking that sqlmap's ``*`` marker be placed by the executor's own
#: deterministic path code (:func:`~dast_orchestrator.stages.verify.mark_path_injection`).
ALLOWED_PROBE_ARGS = frozenset({"param", "method", "data", "tags", "level",
                                "risk", "path_injection"})

#: HTTP methods a proposed probe may use.
_ALLOWED_METHODS = frozenset({"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD"})

#: sqlmap's own breadth knobs, clamped so an unattended probe stays bounded no
#: matter what the model asks for.
_LEVEL_RANGE = (1, 5)
_RISK_RANGE = (1, 3)


def validate_probe(tool: str, proposed: "dict[str, Any] | None"
                   ) -> tuple[dict[str, Any], list[str]]:
    """Clean a model-proposed invocation down to what the executor may run.

    Pure: it decides nothing about the target (the executor injects that) and
    runs nothing. It drops keys outside :data:`ALLOWED_PROBE_ARGS`, coerces the
    method to an allowed verb, and clamps sqlmap's breadth — returning the safe
    argument dict and the list of things it had to reject, so the artifact
    records what the model asked for that it was not given.

    :returns: ``(clean_args, violations)``. ``violations`` is empty when the
        proposal was already within bounds.
    """
    proposed = proposed or {}
    clean: dict[str, Any] = {}
    violations: list[str] = []

    for key, value in proposed.items():
        if key not in ALLOWED_PROBE_ARGS:
            violations.append(f"dropped unsupported argument {key!r}")
            continue
        if key == "method":
            method = str(value or "").upper()
            if method and method not in _ALLOWED_METHODS:
                violations.append(f"rejected method {method!r}")
                continue
            if method:
                clean["method"] = method
        elif key == "path_injection":
            clean["path_injection"] = bool(value)
        elif key in ("level", "risk"):
            lo, hi = _LEVEL_RANGE if key == "level" else _RISK_RANGE
            try:
                n = int(value)
            except (TypeError, ValueError):
                violations.append(f"rejected non-integer {key}={value!r}")
                continue
            clamped = max(lo, min(hi, n))
            if clamped != n:
                violations.append(f"clamped {key} {n} -> {clamped}")
            clean[key] = clamped
        else:
            clean[key] = str(value or "")
    return clean, violations


@dataclass(frozen=True)
class DeclaredSignal:
    """The observable the model commits to before the tool runs.

    Deliberately small and mechanical: substrings that must appear in the tool's
    own output, substrings that must NOT (the *"and not the literal {{7*7}}"*
    half of a template-injection check), and whether the tool's own machinery
    must report a confirmed finding. A signal with none of the three is a
    non-prediction and :func:`check_signal` returns ``None`` for it.
    """

    expect: tuple[str, ...] = ()
    reject: tuple[str, ...] = ()
    require_tool_confirmed: bool = False
    description: str = ""

    @property
    def is_empty(self) -> bool:
        return not (self.expect or self.reject or self.require_tool_confirmed)

    @classmethod
    def from_dict(cls, data: "dict[str, Any] | None") -> "DeclaredSignal":
        data = data or {}
        as_tuple = lambda v: tuple(  # noqa: E731
            s for s in (v if isinstance(v, list) else [v]) if isinstance(s, str) and s
        )
        return cls(
            expect=as_tuple(data.get("expect")),
            reject=as_tuple(data.get("reject")),
            require_tool_confirmed=bool(data.get("require_tool_confirmed")),
            description=str(data.get("description") or ""),
        )

    def as_dict(self) -> dict[str, Any]:
        return {
            "expect": list(self.expect),
            "reject": list(self.reject),
            "require_tool_confirmed": self.require_tool_confirmed,
            "description": self.description,
        }


#: The declaration held: every string the model named behaved as it predicted.
SIGNAL_OBSERVED = "observed"
#: The declaration was checked and did not hold.
SIGNAL_ABSENT = "absent"
#: The model committed to nothing a comparator could test.
SIGNAL_NOT_DECLARED = "not-declared"
#: The model declared something, and nothing could be checked against it: the
#: probe never ran, the tool reported no observation at all, or every string it
#: named is also in the invocation the executor sent. Distinct from
#: :data:`SIGNAL_ABSENT`, and the distinction is the point — "we could not look"
#: and "we looked and it was not there" must never share a column.
SIGNAL_NOT_CHECKABLE = "not-checkable"


@dataclass(frozen=True)
class SignalCheck:
    """Whether the declared signal was observed in the tool's output."""

    observed: "bool | None"   #: None when nothing could be checked.
    detail: str
    #: One of :data:`SIGNAL_OBSERVED` / :data:`SIGNAL_ABSENT` /
    #: :data:`SIGNAL_NOT_DECLARED` / :data:`SIGNAL_NOT_CHECKABLE`. ``observed``
    #: alone cannot separate the two ``None`` cases, and they mean opposite
    #: things about the model.
    code: str = SIGNAL_NOT_DECLARED

    def as_dict(self) -> dict[str, Any]:
        return {"observed": self.observed, "detail": self.detail,
                "code": self.code}


def _observation_text(tool_result: "dict[str, Any]") -> str:
    """What the tool reported *observing*, and nothing the wrapper concluded.

    The wrapper's own verdict prose (``detail``) is excluded on purpose: matching a
    declared substring against it would test whether the model guessed the wrapper's
    vocabulary, not whether its prediction about the application held.

    What is left is the tool's own extract (``evidence``) and its raw output
    (``stdout_excerpt``) — the browser wrapper's rendered DOM, nuclei's matched
    template, ffuf's result set.
    """
    parts = [
        str(tool_result.get("evidence") or ""),
        str(tool_result.get("stdout_excerpt") or ""),
    ]
    return "\n".join(p for p in parts if p).lower()


#: Words that belong to a tool's own output FORMAT rather than to anything it
#: observed. Discarded from a declared signal like the command echo, and for the
#: same reason: they are satisfied by the *shape* of the output, so they would hold
#: for any finding on any target — including a perfectly patched one. Deliberately
#: not a general stop-word list: each entry is a field name or fixed marker in one
#: wrapper's serialisation, so the set moves only when a tool's output format does.
OUTPUT_FORMAT_WORDS: dict[str, frozenset[str]] = {
    "nuclei": frozenset({
        "matched", "matched-at", "matcher-name", "matcher_name", "template",
        "template-id", "template-url", "template-path", "extracted-results",
        "curl-command", "severity", "info", "host", "type", "timestamp",
    }),
    "sqlmap": frozenset({
        "[info]", "[warning]", "[critical]", "[payload]", "testing",
        "parameter", "starting", "shutting down", "sqlmap",
    }),
    "ffuf": frozenset({
        "results", "commandline", "cmdline", "config", "fuzz", "input",
        "position", "status", "length", "words", "lines", "duration",
    }),
    # The browser wrapper returns the rendered DOM, which is the target's own
    # bytes rather than a serialisation of its verdict. It has no format words:
    # everything in that substrate genuinely came from the application.
    "browser": frozenset(),
}


def format_words(tool: "str | None") -> frozenset[str]:
    """Output-format vocabulary for one tool; empty for an unknown one.

    Empty rather than a union, deliberately: discarding a term because some
    *other* tool's format contains it would throw away a real prediction.
    """
    return OUTPUT_FORMAT_WORDS.get(str(tool or "").lower(), frozenset())


def check_signal(signal: DeclaredSignal,
                 tool_result: "dict[str, Any]") -> SignalCheck:
    """Was the model's declared signal actually observed in the tool output?

    Checked against what the tool reported observing (:func:`_observation_text`)
    — never against the wrapper's own verdict prose, and never against a string
    that is already in the invocation the executor sent.

    Two things are discarded before the check because they would hold on a perfectly
    patched instance: the **echo** (a term already in the invocation the executor
    sent — every tool prints its command back) and the **format words** (field names
    from the tool's own serialisation; see :data:`OUTPUT_FORMAT_WORDS`).

    A round that never dispatched, or whose tool reported no observation at all,
    yields :data:`SIGNAL_NOT_CHECKABLE` — there was no output to look in, and
    recording that as a failed prediction is the missing-measurement-as-measured-zero
    conflation this project forbids everywhere.
    """
    if signal.is_empty:
        return SignalCheck(None, "the model declared no checkable signal",
                           SIGNAL_NOT_DECLARED)
    if str(tool_result.get("outcome") or "") == NOT_ATTEMPTED:
        return SignalCheck(None, "the probe never ran, so there was no output "
                                 "to check the prediction against",
                           SIGNAL_NOT_CHECKABLE)

    command = str(tool_result.get("command") or "").lower()
    fmt = format_words(tool_result.get("tool"))

    def why_untestable(term: str) -> "str | None":
        """Why this term would hold regardless of what the target did, or ``None``.

        Two ways, kept apart because they are different mistakes and a reader
        must be able to tell which was made: the term is already in the
        invocation we sent, or it is a word from the tool's own output *format*
        rather than from anything it observed. See :data:`OUTPUT_FORMAT_WORDS`.
        """
        low = term.lower()
        if low in command:
            return "echo"
        if any(low in word or word in low for word in fmt):
            return "format"
        return None

    reasons = {t: why_untestable(t) for t in signal.expect + signal.reject}
    echoed = sorted({t for t, r in reasons.items() if r == "echo"})
    formatted = sorted({t for t, r in reasons.items() if r == "format"})
    expect = [e for e in signal.expect if reasons.get(e) is None]
    reject = [r for r in signal.reject if reasons.get(r) is None]

    text = _observation_text(tool_result)
    if (expect or reject) and not text:
        return SignalCheck(None, "the tool reported no observation to search: "
                                 f"{expect + reject} could not be checked",
                           SIGNAL_NOT_CHECKABLE)
    # `reject` is a veto, never an observation. A signal left with nothing but
    # rejections is satisfied by a tool that found nothing at all — which is
    # how the remaining four `contradiction` rounds in the corpus arose, each a
    # refutation whose "do not let `image/png` come back" held vacuously.
    if not (expect or signal.require_tool_confirmed):
        discarded = "; ".join(
            part for part in (
                f"{echoed} is in the invocation the executor sent" if echoed else "",
                f"{formatted} belongs to the tool's own output format, not to "
                "anything it observed" if formatted else "",
            ) if part
        )
        detail = (f"every declared string was untestable: {discarded}"
                  if discarded and not reject else
                  "the signal has no positive half: an absent rejection is not "
                  "an observation, so nothing here could confirm the finding")
        return SignalCheck(None, detail, SIGNAL_NOT_CHECKABLE)

    missing = [e for e in expect if e.lower() not in text]
    present_bad = [r for r in reject if r.lower() in text]
    tool_ok = (not signal.require_tool_confirmed) or (
        tool_result.get("outcome") == CONFIRMED)
    observed = not missing and not present_bad and tool_ok
    notes: list[str] = []
    if missing:
        notes.append(f"expected {missing} not in output")
    if present_bad:
        notes.append(f"rejected {present_bad} present in output")
    if signal.require_tool_confirmed and not tool_ok:
        notes.append("tool did not report a confirmed finding")
    if observed:
        notes.append("all declared conditions met")
    if echoed:
        notes.append(f"ignored {echoed}: also in the invocation sent")
    if formatted:
        notes.append(f"ignored {formatted}: the tool's own output format")
    return SignalCheck(observed, "; ".join(notes),
                       SIGNAL_OBSERVED if observed else SIGNAL_ABSENT)


# -- the round loop's contract --------------------------------------------
#
# Verification is one bounded loop per finding: the model proposes an
# invocation, a tool runs it, the wrapper classifies the raw output, and the
# model reads that output and either concludes or refines. Everything below is
# the *contract* of that loop — the records it accumulates and the rule that
# turns its two readings into the one reported category. The loop itself is I/O
# and lives in :mod:`dast_orchestrator.analysis.verify_loop`.

#: Rounds a loop may run before it must conclude. Three is propose → react →
#: refine — enough to correct an invocation once and act on the result — and, since
#: every round re-sends the transcript, a cost ceiling as much as a termination
#: guarantee. Overridden with ``VERIFY_MAX_ROUNDS``.
DEFAULT_MAX_ROUNDS = 3

#: The one axis a verification configuration still varies.
#:
#: Tool choice is always the deterministic table (:func:`selected_tool`): keyed on
#: the ZAP rule, reproducible, and the tool the model would have named the vast
#: majority of the time anyway. The model-picks-the-tool option was removed
#: 2026-11-02 — it was never properly wired and bought nothing over the lookup.
#:
#: ``invocation`` — HOW it is called and when to stop: ``llm`` is the round loop,
#: ``deterministic`` the fixed single-shot invocation built from the finding. Default
#: ``llm`` — invocation is the axis on which the model earns its cost.
INVOCATIONS = ("llm", "deterministic")

#: The fully-deterministic configuration: the table's tool, invoked single-shot.
#: No key, no spend, and the baseline every LLM configuration is measured against.
#: It must stay first-class — a mode with no deterministic path would make "the
#: model verifies well" unfalsifiable. ``tool_choice`` stays recorded as ``table``
#: for provenance, the only value it has ever taken.
DETERMINISTIC_CONFIG = {"tool_choice": "table", "invocation": "deterministic"}

#: The two agreement states recorded on every looped record. ``flagged`` is not
#: an error: it is the classification-audit signal, and counting it is how the
#: disagreement rate between the wrapper's fixed rules and the model's reading
#: is obtained for free, on the model's own tool calls.
AGREE = "agree"
FLAGGED = "flagged"


def tool_ran(tool_result: "dict[str, Any]") -> bool:
    """Did this tool invocation validly put the question to the target?

    The load-bearing distinction of the whole layer: *"the tool tested it and
    found nothing"* and *"the tool never got to test it"* must never be read
    alike, because only the first is a refutation. A wrapper says so itself via
    ``tested``; the fallback reading is for records written before it did, where
    the non-run class is exactly the ``inconclusive`` verdicts on which the tool
    qualified its own basis (nuclei with no templates, ffuf whose requests never
    landed, sqlmap on a page comparison it had already called unreliable).
    """
    outcome = tool_result.get("outcome")
    if outcome in (NOT_ATTEMPTED, None):
        return False
    if tool_result.get("timed_out"):
        return False
    tested = tool_result.get("tested")
    if tested is None:
        return not (outcome == INCONCLUSIVE and tool_result.get("tool_warnings"))
    return bool(tested)


#: Categories the model may assign at the end of a loop. ``not-attempted`` is
#: deliberately absent: whether a probe happened is an observation the executor
#: makes, never a judgement the model is asked for.
LLM_CATEGORIES = (CONFIRMED, REFUTED, INCONCLUSIVE)


def resolve_verdict(wrapper_outcome: "str | None",
                    llm_category: "str | None",
                    ran: bool = True) -> tuple[str, str]:
    """The reported category, and whether the two readings agreed.

    The rule in one sentence: **the model's category is reported, except it can
    never produce a ``confirmed`` the tool's own machinery did not also report,
    and a tool that did not validly run cannot be rescued.**

    ==================== ============ ============ ================
    wrapper \\ model      confirmed    refuted      inconclusive
    ==================== ============ ============ ================
    confirmed            confirmed    refuted ⚑    inconclusive ⚑
    refuted              **inconc ⚑** refuted      inconclusive ⚑
    inconclusive         **inconc ⚑** refuted ⚑    inconclusive
    did not validly run  wrapper ⚑    wrapper ⚑    wrapper
    ==================== ============ ============ ================

    The model may downgrade and raise doubt freely — that is falsification, the
    thing this layer is measurably good at. The two bold cells are the only
    place it is blocked, and they are what keeps a reported ``confirmed``
    trustworthy: the model's unbacked "yes" lands as a *flagged* inconclusive,
    a countable disagreement rather than silent trust. The bottom row is the
    integrity floor — a non-run is never a verdict.

    Every disagreement is recorded, so the blocked cells are measurable. **If
    the audit later shows the model right in them — wrapper false negatives —
    loosen the carve-out with that data, not ahead of it.**

    :param wrapper_outcome: the deterministic wrapper's reading of the final
        round's raw output.
    :param llm_category: the model's own category, or ``None`` when no model
        ran (the fully-deterministic configuration).
    :param ran: whether the tool validly ran — :func:`tool_ran` of the same
        result. ``False`` puts the resolution on the bottom row.
    :returns: ``(reported_category, agreement)`` where agreement is
        :data:`AGREE` or :data:`FLAGGED`.
    """
    wrapper = wrapper_outcome or NOT_ATTEMPTED
    if llm_category not in LLM_CATEGORIES:
        # No model reading to resolve against: the wrapper is the verdict and
        # there is nothing to agree or disagree with.
        return wrapper, AGREE
    agreement = AGREE if wrapper == llm_category else FLAGGED
    if not ran or wrapper == NOT_ATTEMPTED:
        return wrapper, agreement
    if llm_category == CONFIRMED and wrapper != CONFIRMED:
        # The no-upgrade carve-out. Not the model's category and not the
        # wrapper's either: an explicit "the model says yes and the tool's own
        # machinery does not back it", which is neither a confirmation nor a
        # refutation.
        return INCONCLUSIVE, FLAGGED
    return llm_category, agreement


@dataclass(frozen=True)
class RoundRecord:
    """One round of the loop: what the model asked for, and what came back.

    Kept per round rather than only for the last one so the *trajectory* is
    visible — a loop that refuted at round 1 and a loop that reached the same
    refutation only after correcting its parameter are different results, and
    a record holding only the final round cannot tell them apart.
    """

    index: int
    tool: "str | None"
    arguments: dict[str, Any] = None  # type: ignore[assignment]
    #: What the model committed to observing this round, before the tool ran.
    #: Kept even though the model now makes the final call: a stated,
    #: mechanically checkable prediction is what makes a round falsifiable
    #: rather than a narration of whatever the output turned out to be.
    declared_signal: dict[str, Any] = None  # type: ignore[assignment]
    signal_check: dict[str, Any] = None  # type: ignore[assignment]
    #: The wrapper's fixed-rule reading of THIS round's raw output.
    wrapper_outcome: str = INCONCLUSIVE
    tool_ran: bool = True
    tool_result: dict[str, Any] = None  # type: ignore[assignment]
    #: What the model made of the output, and whether it wanted another round.
    model_note: str = ""
    model_category: "str | None" = None
    violations: tuple[str, ...] = ()
    #: Whether a model proposed this round's invocation. False for the
    #: deterministic single-shot probe, and for a round a budget refused before
    #: any model was consulted. Recorded because several counters are only
    #: meaningful over model-driven rounds — a deterministic round carries no
    #: declared signal, and counting it as *the model declining to declare one*
    #: conflates "was not asked" with "would not answer".
    model_directed: bool = False

    def as_dict(self) -> dict[str, Any]:
        return {
            "index": self.index,
            "tool": self.tool,
            "model_directed": self.model_directed,
            "arguments": self.arguments or {},
            "declared_signal": self.declared_signal or {},
            "signal_check": self.signal_check or {},
            "wrapper_outcome": self.wrapper_outcome,
            "tool_ran": self.tool_ran,
            "tool_result": self.tool_result or {},
            "model_note": self.model_note,
            "model_category": self.model_category,
            "violations": list(self.violations),
        }


#: Why a selected finding was never probed — split out because ``not-attempted``
#: had one meaning in the artifact and several causes, and a reader must tell a
#: finding the BUDGET dropped from one nothing could ever have tested.
#: :data:`NA_NO_TOOL` is the one that indicts the table, not the budget (a rescan
#: flagged on risk alone but routed nowhere — the shape of the rule-40026 defect),
#: so counting it is how the next such rule is found by a number, not a corpus.
NA_NO_TOOL = "no-tool-routed"
NA_NO_PROBE = "no-probe-url"
NA_CAPPED = "budget"
#: A synthesis claim whose own disposition says no tool applies — ``self-evident``
#: (provable from its cited findings) or ``out-of-scope`` (the manual-evaluation
#: set). These are decisions, not gaps, so they are not counted as
#: :data:`NA_NO_TOOL`.
NA_BY_DISPOSITION = "no-tool-applies"
#: A tool WAS routed and a clean URL WAS derived, but the flagged parameter is not
#: in the request that tool would send (sqlmap asked for a parameter in neither URL
#: nor body; nuclei/ffuf/browser asked about a form-body field, and none sends a
#: body). Its own code, not :data:`NA_NO_PROBE` (which means no URL could be built):
#: here the URL is fine and the *question* cannot be put.
NA_TOOL_CANNOT_REACH = "tool-cannot-reach-parameter"
NA_REASONS = (NA_NO_TOOL, NA_NO_PROBE, NA_CAPPED, NA_BY_DISPOSITION,
              NA_TOOL_CANNOT_REACH)


# -- the sibling population's own outcome ----------------------------------
#
# Sibling probes are not the flagged population and they do not share its
# vocabulary. The four outcomes above answer "is what ZAP reported real?" about
# a URL the scanner actually visited; a sibling probe asks a different question
# at a URL this pipeline BUILT, and one of its answers has no counterpart in
# that vocabulary at all.

#: A **sibling probe** whose constructed URL is not a page the application serves.
#: Its own name, not :data:`NOT_ATTEMPTED`: that means *we did not get to it*, while
#: this means we did, asked, and the route the claim predicted does not exist — a
#: result about the claim, which folding into ``not-attempted`` would bury.
SIBLING_UNREACHABLE = "sibling-unreachable"

#: A **sibling probe** at a route the application serves but whose response the probe
#: would not be reading: a redirect (it follows and examines elsewhere) or a server
#: error (it examines an error page). Its own outcome, not :data:`SIBLING_UNREACHABLE`
#: — *unreachable* is a verdict on the prediction (the route does not exist), this is
#: a verdict on the probe (the route exists but cannot be pointed at).
SIBLING_NOT_PROBEABLE = "sibling-not-probeable"

#: Every outcome a sibling record may carry: the four shared with the flagged
#: population, plus the two only this population can produce.
SIBLING_OUTCOMES = OUTCOMES + (SIBLING_UNREACHABLE, SIBLING_NOT_PROBEABLE)


#: Response statuses that mean *this route does not exist*, for the sibling
#: pre-check.
ROUTE_ABSENT_STATUSES = frozenset({404, 410})


def route_probeable(status: "int | None") -> "str | None":
    """Why a sibling route cannot be probed at this status, or ``None``.

    ``None`` from the pre-check itself means *we could not check* and the probe
    runs as it would have before — a missing measurement is never read as a
    measured refusal.

    A 401/403 stays probeable (it is the route's own answer). A 3xx or 5xx does not:
    the probe follows the redirect and reads a different page, or reads an error page,
    so whatever it concludes is about that other page.

    :returns: :data:`SIBLING_UNREACHABLE`, :data:`SIBLING_NOT_PROBEABLE`, or
        ``None`` to proceed.
    """
    if status is None:
        return None
    if status in ROUTE_ABSENT_STATUSES:
        return SIBLING_UNREACHABLE
    if 300 <= status < 400 or 500 <= status < 600:
        return SIBLING_NOT_PROBEABLE
    return None


@dataclass(frozen=True)
class LoopVerdict:
    """What one finding's loop settled on, with both readings kept side by side.

    ``wrapper_verdict`` is not a second opinion obtained at extra cost: it is
    the wrapper's classification of the model's *own* final tool call, so it
    rides along free and audits exactly one thing — the categorisation, since
    the model chose the invocation. That is deliberately narrower than the
    fully-deterministic configuration, which picks its own tool and its own
    invocation and is the independent control.
    """

    finding_id: str
    reported: str
    wrapper_verdict: str
    llm_verdict: "str | None"
    agreement: str
    rounds: tuple[RoundRecord, ...] = ()
    tool: "str | None" = None
    detail: str = ""
    stopped_because: str = ""
    #: One of :data:`NA_REASONS` when this finding was never probed, else "".
    #: Categorical rather than prose so it can be counted; the prose stays in
    #: `detail`, which says the same thing at length.
    not_attempted_reason: str = ""
    #: The class cross-check of a confirmation against the rule it confirms, and
    #: the outcome the class gate moved it FROM when the two disagreed. Both are
    #: ``None`` unless a tool reported ``confirmed`` (see
    #: :func:`...verification.class_gate`, applied in :func:`settle`).
    classification: "dict[str, Any] | None" = None
    outcome_downgraded_from: "str | None" = None

    @property
    def rounds_used(self) -> int:
        return len(self.rounds)

    def as_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "reported_verdict": self.reported,
            "wrapper_verdict": self.wrapper_verdict,
            "llm_verdict": self.llm_verdict,
            "agreement": self.agreement,
            "rounds_used": self.rounds_used,
            "stopped_because": self.stopped_because,
            "not_attempted_reason": self.not_attempted_reason or None,
            "rounds": [r.as_dict() for r in self.rounds],
        }
        # Only present on a confirmation, so a non-confirmed row's shape is
        # unchanged (the summary and SARIF read them with `.get`).
        if self.classification is not None:
            out["classification"] = self.classification
        if self.outcome_downgraded_from is not None:
            out["outcome_downgraded_from"] = self.outcome_downgraded_from
        return out
