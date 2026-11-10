"""The experimental LLM screening arm — the triage stage's pass 1 (per-endpoint, rescan
proposals only; the control is :mod:`~dast_orchestrator.domain.rescan_table`, pass 2 is
:mod:`~dast_orchestrator.analysis.synthesize`), plus the shared ``OpenRouterCorrelator``
client the verify loop reuses.

One call per candidate endpoint through the official OpenRouter SDK (no LangChain) — the
request assembled here is the whole of it, and every output-affecting knob is a
version-controlled constant copied into the artifact's ``llm`` block. The model may
re-flag a finding or propose a correlated-synthesis finding tied to no single alert
(hence the second SARIF rule-id namespace). → DECISIONS.md.
"""

from __future__ import annotations

import json
import os
import random
import re as _re
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Iterable

from dast_orchestrator.analysis import join
from dast_orchestrator.context import evidence
from dast_orchestrator.foundation import prompts
from dast_orchestrator.domain import verification
from dast_orchestrator.adapters import retrieval as retrieval_mod
from dast_orchestrator.analysis.join import AlertGroup, Bundle, shared_handlers
from dast_orchestrator.adapters.noir_runner import classify_guard

# --- pinned request parameters -------------------------------------------

#: **Pass 1 — per-endpoint triage.** The workload is many small calls, so unit
#: price and latency dominate and *reasoning is a liability*: this model reasons
#: before answering
#: and bills that from the completion budget, which is what produces the
#: truncation-and-split events. Cheapest tier that still supports a strict
#: schema and a seed, and served by 29 providers so the account's privacy
#: settings cannot leave it with none.
#:
#: Dated snapshot, never a floating alias (``:free``, ``-latest``) — a thesis
#: number has to be re-runnable against the same weights.
#: Override with ``--screening-model`` / ``TRIAGE_SCREENING_MODEL``.
MODEL = "deepseek/deepseek-v4-flash-0731"

#: Deterministic-as-possible decoding. OpenRouter forwards ``seed`` to providers
#: that support it, which is not a reproducibility guarantee — hence the raw
#: response being archived rather than assumed re-derivable.
TEMPERATURE = 0.0
SEED = 20260817

#: Output ceiling. One verdict object per alert (~90 tokens) *plus* this model's
#: reasoning, which is billed and budgeted as completion tokens, so the ceiling
#: has to cover both. A 45-alert endpoint was lost to truncation at 4096.
MAX_TOKENS = 8192

#: OpenRouter provider routing applied to EVERY call, in every stage, for every
#: model (there is one client and one send site, so this is uniform by
#: construction). It is a *preference*, not a single hardcoded provider — the
#: model was chosen for being served by many providers so the account's privacy
#: filter cannot leave it with none — and it fixes two failure modes of leaving
#: routing to chance: a single slow, failure-prone provider, and providers that
#: silently ignore the strict schema / seed and break both determinism and the
#: minItems contract.
#:
#: * ``require_parameters`` — only providers that honour this request's params
#:   (seed + strict structured output); a provider that drops them is skipped.
#: * ``sort: throughput`` — prefer the fast ones, so a blind draw cannot land the
#:   whole run on a slow provider.
#: * ``data_collection: deny`` — keep the privacy stance the model was chosen for.
#: * ``allow_fallbacks`` — stay available across the many providers.
DEFAULT_PROVIDER_PREFERENCES: "dict[str, Any]" = {
    "require_parameters": True,
    "sort": "throughput",
    "data_collection": "deny",
    "allow_fallbacks": True,
}


def build_provider(pin: str = "") -> "dict[str, Any]":
    """The ``ProviderPreferences`` (as a dict the SDK accepts) for ONE model's calls.

    Each model slot (triage, synthesis, verify) carries its OWN provider setting
    — a plain provider slug, or a comma list of them — so a stage's several
    models can each be pinned to a provider that actually serves them, without
    packing model→provider maps into one flag. A non-empty ``pin`` restricts
    routing to those providers with fallbacks OFF, so the call is served by them
    or it fails — the fully-reproducible mode for a final run. Empty ``pin`` (the
    default) uses :data:`DEFAULT_PROVIDER_PREFERENCES`, the throughput/
    require-parameters routing preference.
    """
    only = [p.strip() for p in (pin or "").split(",") if p.strip()]
    if only:
        return {"only": only, "allow_fallbacks": False}
    return dict(DEFAULT_PROVIDER_PREFERENCES)


def sampling_params(temperature: float,
                    capabilities: "dict[str, Any] | None") -> "dict[str, Any]":
    """The decoding parameters for one call — ``temperature`` and ``seed`` — with
    any the served model is KNOWN not to accept dropped.

    One send site serves every stage (screening, synthesis, verify), so this is
    where model-call configuration is made uniform AND compatible across models.

    :param capabilities: :func:`model_capabilities` for this model, or ``None``
        when the catalogue could not be read. ``None`` (unknown) sends both — the
        determinism default, "temperature 0 when it can be set" — because the
        pinned models accept them and a missing measurement must not silently
        disable the seed. A capability that explicitly reports a parameter
        unsupported (a frontier model that rejects ``temperature``/``seed``, e.g.
        Claude Fable 5.1, which removed the sampling parameters) drops it, so the
        shared call stays compatible instead of failing with a 400.
    """
    params: dict[str, Any] = {"temperature": temperature, "seed": SEED}
    if capabilities is not None:
        if capabilities.get("temperature") is False:
            params.pop("temperature")
        if capabilities.get("seed") is False:
            params.pop("seed")
    return params

#: Transient upstream conditions worth one more try. Parallelising pass 1 makes
#: rate limiting a *predictable* failure rather than a rare one — six workers can
#: trip a per-minute ceiling the sequential pass never approached — and a 429
#: that kills an endpoint costs a verdict for a reason that has nothing to do
#: with the model's judgment.
TRANSIENT_MARKERS = (
    "429", "rate limit", "rate-limit", "too many requests",
    "500", "502", "503", "504", "timeout", "timed out",
    "connection reset", "connection error", "temporarily",
    # A connection dropped mid-response (`httpx.RemoteProtocolError: Server
    # disconnected …`) is a textbook transient, but matched none of the markers
    # above, so it was re-raised and lost a whole paid-for baseline row.
    "server disconnected", "remote protocol", "incomplete read",
    "connection aborted", "peer closed",
    # OpenRouter's generic wrapper when the upstream PROVIDER fails without a
    # classifiable status code — observed as 4 of 5 concurrent synthesis samples
    # dying on one hard-pinned provider while the 5th succeeded, i.e. an
    # intermittent upstream hiccup under concurrency (what the jittered backoff
    # is for), not a bad request. Without this the samples die un-retried and
    # the synthesis reproducibility score collapses to 1 sample.
    "provider returned error",
)
#: The prompt itself was larger than the model's input context window — a
#: distinct failure from a *truncated* answer (that overran the output ceiling).
#: The provider rejects it with a 400 before generating anything, so it is never
#: transient and retrying the same prompt cannot help; only a smaller corpus can.
#: Synthesis is the one place this bites — a whole-corpus pass on a large target
#: (Cacti, 342 endpoints) — so it must degrade to "no synthesis this run" rather
#: than escape as a raw provider error and take the run down.
CONTEXT_OVERFLOW_MARKERS = (
    "context length", "context_length", "context window", "maximum context",
    "too many tokens", "reduce the length", "prompt is too long",
    "input is too long", "maximum prompt length",
)
#: Attempts per call for a transient failure (the first is not a retry).
MAX_TRANSIENT_ATTEMPTS = 3
#: Base of the exponential backoff, in seconds.
TRANSIENT_BACKOFF_SECONDS = 2.0

#: Ceiling for the retry of a chunk that truncated and cannot be split further.
#: A single alert has no smaller form, so the only remaining lever is more room:
#: qwen3-235b reasons enough to exhaust 8192 tokens on one alert, where
#: deepseek-v4-flash does not.
RETRY_MAX_TOKENS = 24576

#: Starting alerts per call, enforced by chunking rather than by dropping.
#: Bundles are wildly uneven (one collapsed to 45 findings; the median has 4)
#: and no single bundle may exhaust the output budget. Lowered 12 -> 6 after a
#: 10-alert chunk still hit the ceiling; the caller additionally halves a chunk
#: that truncates, so this is the starting size, not the guarantee.
MAX_ALERTS_PER_CALL = 6

#: The default prompt: the newest ``prompts/screening/screening.v*.md`` on disk. A
#: run may pin an older one (``--screening-prompt``), which is what makes a prompt
#: A/B a sheet row rather than a source edit — see
#: :mod:`dast_orchestrator.foundation.prompts`. The version lives in the filename,
#: so it cannot drift from the text.
PROMPT_VERSION = prompts.load("screening").version

#: How much a pass-1 call is told about the endpoints it is *not* being shown.
#:
#: ``none``
#:     One endpoint per call and nothing else — the shape every recorded run so
#:     far used, kept as the A/B baseline rather than as a fallback.
#: ``siblings``
#:     Adds, per alert, where else in this scan the same ZAP rule fired.
#: ``full``
#:     Adds the shared-handler links as well: which of those sibling routes run
#:     the *same handler code* as this one.
PASS1_CONTEXT_LEVELS = ("none", "peers", "full")
DEFAULT_PASS1_CONTEXT = "full"

#: Caps on the cross-endpoint block, so context never crowds out evidence. Pass
#: 1's value is depth on one endpoint; this is a sketch of its neighbourhood,
#: not a second corpus.
#:
#: **The sibling routes named are only the ones that share a handler.** Listing
#: every route carrying the same rule is long (rules like ``10112`` fire on
#: hundreds), repeated on every chunk, and says little beyond "this rule is
#: common" — which a count says in four tokens; scoping to handler-linked routes
#: keeps exactly the signal the shared-handler contradictions are found on.
MAX_SIBLING_ROUTES_PER_RULE = 8
MAX_SHARED_HANDLER_LINKS = 5

#: How much of each Noir signal survives into the prompt. Snippets dominate the
#: artifact; the first lines carry the relevant call, the rest is noise.
MAX_SIGNALS_PER_CATEGORY = 8
MAX_SNIPPET_CHARS = 300
MAX_EVIDENCE_CHARS = 300

SYSTEM_PROMPT = prompts.load("screening").text

#: Structured-output contract. ``strict`` plus ``additionalProperties: false``
#: so a malformed response fails at the provider rather than half-parsing here.
RESPONSE_SCHEMA: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "required": ["alert_verdicts"],
    "properties": {
        "alert_verdicts": {
            "type": "array",
            "description": "Exactly one entry per alert given, same finding_id.",
            # `minItems`/`maxItems` are set per call by :func:`verdicts_schema`.
            # Without them this description is the only thing asking for one verdict
            # per alert, and a description is not a contract: a model can silently
            # return fewer verdicts than asked while reporting zero failed calls,
            # because a short-but-valid answer is not an error.
            "items": {
                "type": "object",
                "additionalProperties": False,
                "required": [
                    "finding_id",
                    "needs_rescan",
                    "verdict",
                    "confidence",
                    "reasoning",
                    "suggested_tool",
                ],
                "properties": {
                    "finding_id": {"type": "string"},
                    "needs_rescan": {"type": "boolean"},
                    "verdict": {
                        "type": "string",
                        "enum": [
                            "likely-true-positive",
                            "likely-false-positive",
                            "undecidable-without-verification",
                            "self-evident-no-verification-needed",
                        ],
                    },
                    "confidence": {
                        "type": "string",
                        "enum": ["low", "medium", "high"],
                    },
                    "reasoning": {"type": "string"},
                    "suggested_tool": {
                        "type": "string",
                        "enum": ["sqlmap", "nuclei", "ffuf", "interactsh", "none"],
                    },
                },
            },
        },
    },
}


def verdicts_schema(expected: int) -> dict[str, Any]:
    """:data:`RESPONSE_SCHEMA` with the verdict count pinned to this call's alerts.

    The pass asks about *n* alerts and needs *n* verdicts back. Leaving that to
    the prose description cost 18–30% of every cheap-model run's verdicts, with
    ``failed_calls: 0`` — the model returned valid JSON that was simply short,
    which no error path could see. Under ``strict`` structured output the
    provider has to satisfy the bounds, so the contract is enforced where it is
    stated rather than hoped for.

    A provider that ignores the bounds anyway is still handled: the caller
    re-asks for whatever is missing (:func:`missing_verdict_ids`).
    """
    import copy

    schema = copy.deepcopy(RESPONSE_SCHEMA)
    verdicts = schema["properties"]["alert_verdicts"]
    verdicts["minItems"] = expected
    verdicts["maxItems"] = expected
    return schema


def missing_verdict_ids(response: dict[str, Any],
                        asked: "list[str]") -> list[str]:
    """Ids that were asked about and have no verdict in this response."""
    answered = {
        str(v.get("finding_id", ""))
        for v in (response or {}).get("alert_verdicts", [])
    }
    return [fid for fid in asked if fid not in answered]


class LlmError(RuntimeError):
    """Raised when the model call fails or returns something unusable.

    `kind` is a short machine-readable tag so the artifact can report *why*
    calls failed rather than just how many did. The first Phase 3 run produced
    three distinct causes that a single error message hid from view.
    """

    def __init__(self, message: str, kind: str = "unknown") -> None:
        super().__init__(message)
        self.kind = kind


#: A cost ceiling that is not a ceiling. Every budget in this pipeline defaults
#: to it, on purpose: a cap that fires part-way through leaves a run whose
#: numbers are a lower bound on a question nobody asked, which is worse than a
#: run that cost more than expected. Budgets exist to stop a *mistake* running
#: all night, not to shape a result.
UNLIMITED = -1.0

#: How many failure messages :class:`LlmUsage` keeps, and how long each may be:
#: enough to name a systematic cause, bounded so a failing run stays small.
MAX_FAILURE_DETAILS = 20
MAX_FAILURE_DETAIL_CHARS = 300

#: Default ceiling on what one *run* may spend across all its stages, in USD.
#: A real number rather than :data:`UNLIMITED`, because the thing a budget
#: protects against is a mistake — a wrong model id, a runaway retry, a sheet
#: left running — and a mistake is exactly the case where nobody is watching.
#: A run that legitimately needs more says so; a full two-pass triage on this
#: target costs cents, so $1 is ample headroom and still stops a runaway inside a
#: minute.
DEFAULT_RUN_MAX_COST_USD = 1.0


def over_budget(spent: float, cap: float) -> bool:
    """Whether ``spent`` has reached a cap. A negative cap is no cap."""
    return cap is not None and cap >= 0 and spent >= cap


def headroom(stage_cap: float, run_cap: float, prior: float) -> float:
    """What one stage may spend, given both ceilings and the run's earlier spend.

    The one place the two ceilings combine: the stage cap bounds this stage's own
    spend, the run cap bounds ``prior`` plus it, so ``prior`` is subtracted exactly
    once. A run already past its cap leaves ``0.0``, never no cap.

    :param stage_cap: ceiling on this stage's own spend; negative means none.
    :param run_cap: ceiling on the whole run's spend; negative means none.
    :param prior: what earlier stages of the same run already spent.
    :returns: the tighter limit, or :data:`UNLIMITED` when neither cap is set.
    """
    caps = []
    if stage_cap is not None and stage_cap >= 0:
        caps.append(stage_cap)
    if run_cap is not None and run_cap >= 0:
        # Rounded below any price a provider reports, so `0.10 - 0.08` binds
        # at a spend of 0.02 rather than a float's width above it.
        caps.append(max(0.0, round(run_cap - prior, 9)))
    return min(caps) if caps else UNLIMITED



def _selected_provider(metadata: Any) -> str | None:
    """Which upstream provider actually served a call.

    It lives at ``metadata.endpoints.available[*].selected``, **not** under
    ``metadata.attempts`` — that field is always ``None`` and there is a scalar
    ``attempt`` counter beside it, so the obvious-looking `attempts[-1].provider`
    silently produced ``None`` on every call this project has ever made.

    That matters because one model's unit price can step several-fold mid-sheet
    for the same model, region and routing strategy depending on which endpoint
    served the call. Without this field a cost difference between two configurations
    cannot be distinguished
    from a cost difference between two providers, which makes every dollar
    comparison in the project un-attributable.

    Defensive throughout: the shape is the SDK's, it is opt-in behind a header,
    and a provider name is worth having when available and never worth an
    exception when not.
    """
    endpoints = getattr(metadata, "endpoints", None)
    for endpoint in (getattr(endpoints, "available", None) or []):
        if getattr(endpoint, "selected", False):
            return getattr(endpoint, "provider", None)
    return None


def model_vendor(model_id: "str | None") -> str:
    """The model's vendor — the segment before ``/`` in an OpenRouter id.

    ``deepseek/deepseek-v4-flash-0731`` -> ``deepseek``. This is *who built the
    model*, distinct from ``provider`` (which upstream endpoint served the call).
    Both belong in the record: the thesis reports cost and behaviour per model
    vendor, and a bare id makes that a string-parse at read time on every row.
    """
    model_id = model_id or ""
    return model_id.split("/", 1)[0] if "/" in model_id else ""


@dataclass
class LlmUsage:
    """Per-run accounting, stored in the artifact so cost is a reported number.

    **Thread-safe**, because pass 1 dispatches its per-endpoint calls through a
    bounded pool: every counter here is a read-modify-write, and unsynchronised
    ``+=`` from several workers silently *loses* increments. A cost or token
    total that is quietly short is worse than no number at all, so all mutation
    goes through the methods below and each takes the lock. The lock is not part
    of the record's identity, hence ``compare=False, repr=False``.
    """

    calls: int = 0
    prompt_tokens: int = 0
    completion_tokens: int = 0
    #: Prompt tokens the provider served from its own cache rather than
    #: reprocessing. The measurement that makes prompt caching falsifiable: both
    #: multi-turn callers here re-send a stable prefix every turn and mark it
    #: cacheable, and without this the only visible effect is a cost that may or
    #: may not have moved for some other reason. `0` on a provider that reports
    #: nothing, which is indistinguishable from a miss — say so rather than
    #: reading it as one.
    cached_prompt_tokens: int = 0
    cost_usd: float = 0.0
    #: Ceiling on this stage's own spend, in USD. :data:`UNLIMITED` (-1) means no
    #: cap, which is the default: a cap that fires mid-run truncates the
    #: experiment, so it has to be asked for rather than assumed.
    stage_max_cost_usd: float = UNLIMITED
    #: Ceiling on the whole run's spend: :attr:`prior_cost_usd` plus this stage's.
    run_max_cost_usd: float = UNLIMITED
    #: Spend already charged to this *run* by earlier stages. Counted against the
    #: run ceiling only, and only once — see :func:`headroom`.
    prior_cost_usd: float = 0.0
    #: Wall-clock limit on the stage, in minutes, and the ``time.monotonic()``
    #: after which no further call starts. ``None`` means no limit. A safety net
    #: against a provider that slows to a crawl, not a scope: a stop records each
    #: unsent call as a ``time_limit`` failure.
    max_minutes: "float | None" = None
    deadline: "float | None" = None
    failures: int = 0
    retries: int = 0
    #: Chunks halved after truncating. Distinct from a retry: the call is not
    #: repeated, it is replaced by two smaller ones.
    splits: int = 0
    #: One record per HTTP call — see :meth:`record_call`. Kept per-call rather
    #: than only aggregated so the writeup can report latency distribution and
    #: which provider actually served each request, not just a run total.
    calls_log: list[dict[str, Any]] = field(default_factory=list)
    #: Guards every counter and the call log against concurrent workers.
    _lock: "threading.Lock" = field(
        default_factory=threading.Lock, compare=False, repr=False
    )

    def note_retry(self) -> None:
        with self._lock:
            self.retries += 1

    def note_split(self) -> None:
        """A chunk halved after truncating — not a retry: the call is replaced."""
        with self._lock:
            self.splits += 1

    def record_tokens(self, usage: Any) -> None:
        """Accumulate one response's tokens and OpenRouter's own reported cost."""
        with self._lock:
            self.calls += 1
            if usage is None:
                return
            self.prompt_tokens += int(getattr(usage, "prompt_tokens", 0) or 0)
            self.completion_tokens += int(getattr(usage, "completion_tokens", 0) or 0)
            self.cached_prompt_tokens += cached_tokens(usage)
            self.cost_usd += float(getattr(usage, "cost", 0.0) or 0.0)

    def headroom_usd(self) -> float:
        """What this stage may spend in all (:func:`headroom`); fixed at construction."""
        return headroom(self.stage_max_cost_usd, self.run_max_cost_usd,
                        self.prior_cost_usd)

    def budget_exhausted(self) -> bool:
        """Whether this stage has reached either cost ceiling.

        Checked *before* a call rather than after, so the cap is a limit on what
        is spent rather than on what has been. Takes the lock: several workers
        ask this concurrently and the answer must not straddle a write.
        """
        with self._lock:
            return over_budget(self.cost_usd, self.headroom_usd())

    def out_of_time(self) -> bool:
        """Whether the stage's wall-clock limit has passed; checked before a call."""
        return self.deadline is not None and time.monotonic() >= self.deadline

    def time_note(self) -> str:
        """One line naming the time limit that stopped the stage."""
        return f"time limit reached: no call starts after {self.max_minutes:g} min"

    def budget_note(self) -> str:
        """One line naming the ceiling that bound and what had been spent."""
        with self._lock:
            if over_budget(self.cost_usd, self.stage_max_cost_usd):
                return (f"stage cost ceiling reached: ${self.cost_usd:.4f} spent "
                        f"of ${self.stage_max_cost_usd:.4f}")
            spent = self.prior_cost_usd + self.cost_usd
            return (f"run cost ceiling reached: ${spent:.4f} spent of "
                    f"${self.run_max_cost_usd:.4f}"
                    + (f" (${self.prior_cost_usd:.4f} of it by earlier stages "
                       "of this run)" if self.prior_cost_usd else ""))

    def record_call(
        self,
        *,
        pass_name: str,
        label: str,
        model_requested: str,
        latency_ms: float,
        result: Any,
        outcome: str,
    ) -> None:
        """Log one model call with its routing, latency and token cost.

        OpenRouter may serve a request from any of several providers, and which
        one answered changes both latency and (with BYOK) price — so the
        provider is recorded per call rather than assumed constant for the run.
        The generation ``id`` is kept because it is the key to look a call up in
        OpenRouter's own dashboard months later.
        """
        usage = getattr(result, "usage", None)
        metadata = getattr(result, "openrouter_metadata", None)
        provider = _selected_provider(metadata)
        choices = getattr(result, "choices", None) or []
        entry = (
            {
                "at": datetime.now(timezone.utc).isoformat(),
                "pass": pass_name,
                "label": label,
                "latency_ms": round(latency_ms, 1),
                "model_requested": model_requested,
                "model_served": getattr(result, "model", None),
                "vendor": model_vendor(model_requested),
                "provider": provider,
                "routing_strategy": getattr(metadata, "strategy", None),
                "region": getattr(metadata, "region", None),
                "generation_id": getattr(result, "id", None),
                "finish_reason": (
                    str(getattr(choices[0], "finish_reason", "") or "") if choices else ""
                ),
                "prompt_tokens": int(getattr(usage, "prompt_tokens", 0) or 0),
                "completion_tokens": int(getattr(usage, "completion_tokens", 0) or 0),
                "cached_prompt_tokens": cached_tokens(usage),
                "cost_usd": float(getattr(usage, "cost", 0.0) or 0.0),
                "outcome": outcome,
            }
        )
        with self._lock:
            self.calls_log.append(entry)
    # Failure causes, keyed by LlmError.kind. A run that loses endpoints has to
    # say which way it lost them, or the reliability of the arm is unassessable.
    failure_kinds: dict[str, int] = field(default_factory=dict)
    #: What each failure said, first :data:`MAX_FAILURE_DETAILS` only — the kind
    #: alone cannot say why an arm answered nothing.
    failure_details: list[dict[str, str]] = field(default_factory=list)

    def record_failure(self, kind: str, detail: str = "") -> None:
        """Count one failure under ``kind``, keeping ``detail`` if given.

        :param detail: the error's own message; credentials are scrubbed and it
            is cut to :data:`MAX_FAILURE_DETAIL_CHARS` before it is kept.
        """
        if detail:
            from dast_orchestrator.foundation import redaction

            detail = redaction.scrub(str(detail))[:MAX_FAILURE_DETAIL_CHARS]
        with self._lock:
            self.failures += 1
            self.failure_kinds[kind] = self.failure_kinds.get(kind, 0) + 1
            if detail and len(self.failure_details) < MAX_FAILURE_DETAILS:
                self.failure_details.append({"kind": kind, "detail": detail})

    def absorb(self, other: "LlmUsage") -> None:
        """Fold another client's accounting into this one.

        Needed only where one *pass* runs several clients — the multi-model
        synthesis ensemble, where each model needs its own client and the stage
        still has to report one cost. The call log keeps every entry, so which
        model made which call stays recoverable from ``model_requested``; only
        the totals are summed. Takes both locks in a fixed order (self first) so
        two concurrent absorbs cannot deadlock.
        """
        with self._lock, other._lock:
            self.calls += other.calls
            self.prompt_tokens += other.prompt_tokens
            self.completion_tokens += other.completion_tokens
            self.cached_prompt_tokens += other.cached_prompt_tokens
            self.cost_usd += other.cost_usd
            self.failures += other.failures
            self.retries += other.retries
            self.splits += other.splits
            for kind, count in other.failure_kinds.items():
                self.failure_kinds[kind] = self.failure_kinds.get(kind, 0) + count
            room = MAX_FAILURE_DETAILS - len(self.failure_details)
            self.failure_details.extend(other.failure_details[:max(room, 0)])
            self.calls_log.extend(other.calls_log)

    def as_dict(self) -> dict[str, Any]:
        return {
            "calls": self.calls,
            "prompt_tokens": self.prompt_tokens,
            "completion_tokens": self.completion_tokens,
            "cached_prompt_tokens": self.cached_prompt_tokens,
            "cost_usd": round(self.cost_usd, 6),
            "failed_calls": self.failures,
            "retried_calls": self.retries,
            "split_chunks": self.splits,
            "failure_kinds": dict(sorted(self.failure_kinds.items())),
            "failure_details": sorted(self.failure_details,
                                      key=lambda d: (d["kind"], d["detail"])),
            "providers": self.providers_used(),
            "latency_ms": self.latency_summary(),
            "calls_log": self.ordered_calls_log(),
        }

    def ordered_calls_log(self) -> list[dict[str, Any]]:
        """The call log in a **stable** order, not the order calls happened to land.

        With a concurrent pass 1, completion order varies run to run, so a
        chronological log would make two runs of the same scan undiffable for no
        reason. Sorting by (pass, endpoint, time) keeps each endpoint's calls in
        the order they were actually made — retries and splits still read
        correctly — while the endpoints themselves sort deterministically. The
        wall-clock ``at`` on every entry preserves the real timing.
        """
        return sorted(
            self.calls_log,
            key=lambda c: (str(c.get("pass", "")), str(c.get("label", "")),
                           str(c.get("at", ""))),
        )

    def providers_used(self) -> dict[str, int]:
        """Call count per upstream provider that actually served a request."""
        counts: dict[str, int] = {}
        for call in self.calls_log:
            name = call.get("provider") or "unknown"
            counts[name] = counts.get(name, 0) + 1
        return dict(sorted(counts.items()))

    def latency_summary(self) -> dict[str, float]:
        """Min / median / max / total call latency, in milliseconds."""
        values = sorted(c["latency_ms"] for c in self.calls_log)
        if not values:
            return {}
        middle = len(values) // 2
        median = (
            values[middle]
            if len(values) % 2
            else (values[middle - 1] + values[middle]) / 2
        )
        return {
            "min": values[0],
            "median": round(median, 1),
            "max": values[-1],
            "total": round(sum(values), 1),
        }


# -- prompt construction ---------------------------------------------------


def _strip_code_fence(text: str) -> str:
    """Unwrap a ```json fence if the model wrapped its JSON in one.

    Structured output is requested with `strict`, so this should never be
    necessary — but one endpoint in the first Phase 3 run came back fenced, and
    discarding a well-formed answer over three backticks would be silly.
    """
    stripped = text.strip()
    if not stripped.startswith("```"):
        return stripped
    body = stripped[3:]
    if body[:4].lower().startswith("json"):
        body = body[4:]
    return body.rsplit("```", 1)[0].strip() if "```" in body else body.strip()


def chunk_alerts(
    findings_for_bundle: list[tuple[str, AlertGroup]],
    size: int = MAX_ALERTS_PER_CALL,
) -> list[list[tuple[str, AlertGroup]]]:
    """Split one endpoint's findings into per-call batches.

    Chunking rather than truncating: every alert still gets asked about, the
    endpoint's static context is simply repeated across the calls it takes. The
    duplicated context costs input tokens, which are the cheap half.
    """
    if size <= 0:
        return [list(findings_for_bundle)]
    return [
        list(findings_for_bundle[i : i + size])
        for i in range(0, len(findings_for_bundle), size)
    ] or [[]]


def _trim(text: str, limit: int) -> str:
    text = " ".join(str(text).split())
    return text if len(text) <= limit else text[: limit - 1] + "…"


def render_static_context(bundle: Bundle) -> dict[str, Any]:
    """Compact the Noir context down to what the prompt actually uses."""
    if not bundle.static_context:
        return {}
    context = bundle.static_context
    rendered: dict[str, Any] = {}
    for category, signals in (context.get("ai_context") or {}).items():
        if not signals:
            continue
        rendered[category] = [
            {
                "kind": signal.get("kind", ""),
                "name": signal.get("name", ""),
                "confidence": signal.get("confidence"),
                "location": f"{signal.get('path', '')}:{signal.get('line', '')}",
                "snippet": _trim(signal.get("snippet", ""), MAX_SNIPPET_CHARS),
                **(
                    {"enforces_login": classify_guard(signal.get("name", ""))}
                    if category == "guards"
                    else {}
                ),
            }
            for signal in signals[:MAX_SIGNALS_PER_CATEGORY]
        ]
    return rendered


def render_alert(finding_id: str, group: AlertGroup,
                 assembler: "evidence.Assembler | None" = None,
                 bundle: Bundle | None = None) -> dict[str, Any]:
    """One alert as the model sees it: ZAP's summary, plus its actual evidence.

    The summary fields alone (rule id, risk, ZAP's confidence and a 300-char
    ``evidence`` string empty on a third of alerts) are very close to the inputs
    the deterministic table decides on, which is why a summary-only prompt could
    never fairly test "the LLM arm adds nothing to triage": the arm was handed the
    lookup table's evidence and asked to out-judge the lookup table.
    """
    rendered = {
        "finding_id": finding_id,
        "zap_plugin_id": group.plugin_id,
        "rule": group.name,
        "risk": group.risk,
        "zap_confidence": group.confidence,
        "parameter": group.param,
        "attack": _trim(group.attack, MAX_EVIDENCE_CHARS),
        "evidence": _trim(group.evidence, MAX_EVIDENCE_CHARS),
        "cwe": group.cweid,
        "instances": group.instances,
        "example_url": group.urls[0] if group.urls else "",
    }
    if assembler is not None:
        pack = assembler.pack(finding_id, group, bundle)
        if pack is not None:
            rendered["evidence_pack"] = pack
    return rendered


def build_cross_endpoint_context(
    bundles: Iterable[Bundle], level: str = DEFAULT_PASS1_CONTEXT,
) -> dict[str, dict[str, Any]]:
    """What each pass-1 call is told about the endpoints it is not being shown.

    Computed **once, before any call is dispatched**, from the finished join. It
    is read-only for the whole pass, which is what lets it exist at all: pass 1
    runs its calls concurrently, and the invariants that make a concurrent run's
    result identical to a sequential one — workers touch no shared state, the
    result does not depend on completion order — are load-bearing and are not
    being traded away for context.

    **This is deliberately not "the sibling verdicts already decided in this
    run"**, which is what ``NEXT_SESSION.md`` proposed. Those verdicts are
    produced by the very calls that would consume them, so feeding them forward
    makes every verdict depend on which endpoints happened to finish first: the
    same scan, the same model and the same seed would then triage differently on
    two runs, and the run-to-run variance the project is trying to *measure*
    would have a new cause that is an artifact of the scheduler. What the model
    actually lacked is the *fact* that it is judging one instance of a rule that
    fired all over the application, and which of those places run the same code —
    and that is knowable up front, from the join, for free.

    :param level: see :data:`PASS1_CONTEXT_LEVELS`. ``none`` returns an empty
        map, which is the A/B baseline rather than a degraded mode.
    :returns: ``endpoint identifier -> context block``, only for endpoints that
        have something to say.
    """
    if level == "none":
        return {}
    bundles = list(bundles)

    routes_by_rule: dict[str, list[str]] = {}
    for bundle in bundles:
        for group in bundle.groups:
            routes = routes_by_rule.setdefault(group.plugin_id, [])
            if bundle.identifier not in routes:
                routes.append(bundle.identifier)

    handlers = (
        shared_handlers(bundles, {b.identifier for b in bundles if b.groups})
        if level == "full" else {}
    )
    # route -> {route: [handlers they share]}, so the block can say *why* two
    # routes are linked rather than only that they are.
    siblings_by_route: dict[str, dict[str, list[str]]] = {}
    for handler, routes in handlers.items():
        for route in routes:
            for other in routes:
                if other != route:
                    siblings_by_route.setdefault(route, {}).setdefault(
                        other, []).append(handler)

    context: dict[str, dict[str, Any]] = {}
    for bundle in bundles:
        links = siblings_by_route.get(bundle.identifier, {})
        rules = {}
        for group in bundle.groups:
            others = [r for r in routes_by_rule.get(group.plugin_id, [])
                      if r != bundle.identifier]
            if not others:
                continue
            entry: dict[str, Any] = {"routes_in_this_scan": len(others) + 1}
            # Named routes only where they run the same handler: see the note on
            # MAX_SIBLING_ROUTES_PER_RULE for what naming all of them cost.
            same_code = sorted(set(others) & set(links))
            if same_code:
                entry["also_on_these_routes_sharing_a_handler"] = (
                    same_code[:MAX_SIBLING_ROUTES_PER_RULE]
                )
            rules[group.plugin_id] = entry
        block: dict[str, Any] = {}
        if rules:
            block["same_rule_elsewhere"] = rules
        if links:
            block["routes_sharing_a_handler"] = {
                route: sorted(names)
                for route, names in sorted(links.items())[:MAX_SHARED_HANDLER_LINKS]
            }
        if block:
            block["note"] = (
                "Route names only: you have NOT been shown these routes' code or "
                "alerts. Use this to judge consistently, never to assert what "
                "they contain."
            )
            context[bundle.identifier] = block
    return context


def build_user_payload(
    bundle: Bundle, findings_for_bundle: list[tuple[str, AlertGroup]],
    cross_endpoint: dict[str, Any] | None = None,
    assembler: "evidence.Assembler | None" = None,
    oracle: "dict[str, Any] | None" = None,
) -> dict[str, Any]:
    """The per-endpoint JSON handed to the model.

    :param oracle: the target's documented vulnerabilities, in oracle-guided
        (``--ceiling``) runs only — see :mod:`dast_orchestrator.analysis.oracle`. First
        in the payload because it is what the model should read before the
        evidence, and because it is byte-identical across every call of the run,
        which extends the cacheable prefix rather than sitting behind the one
        part of the payload that changes per endpoint.
    """
    empty = [
        category
        for category in ("guards", "callees", "sources", "sinks", "validators")
        if not (bundle.static_context or {}).get("ai_context", {}).get(category)
    ]
    return {
        **({"known_vulnerabilities_of_this_target": oracle} if oracle else {}),
        "endpoint": {
            "route": bundle.endpoint_key or f"{bundle.method} {bundle.path}",
            "method": bundle.method,
            "path": bundle.path,
            "static_context_available": bundle.has_static_context,
            "join_tier": bundle.match_how,
            "registered_at": [
                f"{cp.get('path', '')}:{cp.get('line', '')}"
                for cp in (bundle.static_context or {}).get("code_paths", [])
            ],
            "noir_tags": [
                tag.get("name", "")
                for tag in (bundle.static_context or {}).get("tags", [])
            ],
        },
        "static_context": render_static_context(bundle),
        "static_context_categories_not_found": empty,
        # What the tools this pipeline can dispatch actually do — the pass is asked
        # whether an independent tool could settle a finding, so it must be told what
        # the tools are.
        "verification_tools": verification.tool_capabilities(),
        # The handler's own source, once per endpoint rather than once per
        # alert: a six-alert chunk shares one handler, and repeating it would
        # multiply the largest part of the prompt by the chunk size.
        **(
            {assembler.endpoint_context_key: assembler.endpoint_context(bundle)}
            if assembler is not None and assembler.endpoint_context(bundle)
            else {}
        ),
        **({"cross_endpoint_context": cross_endpoint} if cross_endpoint else {}),
        "alerts": [
            render_alert(fid, group, assembler, bundle)
            for fid, group in findings_for_bundle
        ],
    }


def build_messages(
    bundle: Bundle, findings_for_bundle: list[tuple[str, AlertGroup]],
    cross_endpoint: dict[str, Any] | None = None,
    system_prompt: str | None = None,
    assembler: "evidence.Assembler | None" = None,
    oracle: "dict[str, Any] | None" = None,
) -> list[dict[str, str]]:
    return [
        {"role": "system", "content": system_prompt or SYSTEM_PROMPT},
        {
            "role": "user",
            "content": json.dumps(
                build_user_payload(
                    bundle, findings_for_bundle, cross_endpoint, assembler,
                    oracle,
                ),
                indent=1,
            ),
        },
    ]


# -- the call --------------------------------------------------------------


#: Cache lifetime asked for at a breakpoint. ``ephemeral`` is the only value
#: OpenRouter's schema accepts and means the provider's own short-lived cache —
#: minutes, not a stored artifact. Nothing about a run's reproducibility rests on
#: a cache hit: the prefix sent is identical either way, so a miss costs money
#: and changes no verdict.
CACHE_CONTROL = {"type": "ephemeral"}

#: The call sites that mark a cacheable prefix, each switchable on its own.
#: They cache for different reasons and by very different amounts, so pricing
#: them together would hide which one is carrying the saving.
#:
#: **Synthesis is deliberately absent.** Pass 2 marks no breakpoint — it makes
#: ``TRIAGE_SYNTHESIS_REPEATS`` separate calls with one identical prompt, which the
#: provider caches on its own — so there is nothing here to switch off, and a flag
#: pretending otherwise would misattribute a provider behaviour to this code.
CACHE_SITES = ("screening", "verify", "retrieval")

#: Each site's own switch env var. Not a uniform ``<PREFIX>_<SITE>`` any more:
#: the per-site vars carry their stage prefix (``TRIAGE_``/``VERIFY_``) — screening
#: and its retrieval sub-site both run inside the triage stage — so the mapping is
#: explicit.
CACHE_SITE_VARS = {
    "screening": "TRIAGE_PROMPT_CACHE",
    "verify": "VERIFY_PROMPT_CACHE",
    "retrieval": "TRIAGE_PROMPT_CACHE_RETRIEVAL",
}

_OFF = ("0", "false", "no", "off")


def caching_enabled(site: str = "") -> bool:
    """Whether this call site should mark a cacheable prefix.

    The site's own switch (:data:`CACHE_SITE_VARS`) decides, falling back to the
    global ``SHARED_PROMPT_CACHE``, so one switch can still turn everything off
    for an all-or-nothing price comparison while each site stays separately
    controllable for an attributable one.

    The switch exists because of a property of caching rather than a doubt about
    it: a hit returns the tokens the model would have computed anyway, so
    temperature, seed, verdicts and reproducibility are identical either way.
    Nothing in the output can reveal whether it happened, which makes running a
    corpus twice the only honest way to state what it saved.
    """
    if site:
        specific = os.getenv(CACHE_SITE_VARS[site])
        if specific is not None:
            return specific.strip().lower() not in _OFF
    return os.getenv("SHARED_PROMPT_CACHE", "1").strip().lower() not in _OFF


def cached_tokens(usage: Any) -> int:
    """Prompt tokens the provider served from its cache, across reporting shapes.

    Providers put this in different places and some report it not at all, so the
    known shapes are tried in order and anything unrecognised counts as zero.
    **Zero therefore means "not reported OR not hit"** — the two are
    indistinguishable from here, and a run whose total is zero should be read as
    "no evidence of caching", never as "caching was tried and did not work".
    """
    details = getattr(usage, "prompt_tokens_details", None)
    for source, name in ((details, "cached_tokens"),
                         (usage, "cached_tokens"),
                         (usage, "cache_read_input_tokens")):
        if source is None:
            continue
        value = (source.get(name) if isinstance(source, dict)
                 else getattr(source, name, None))
        if value:
            try:
                return int(value)
            except (TypeError, ValueError):
                continue
    return 0


def _mark_cache_prefix(conversation: list[dict[str, Any]],
                       prefix: int, site: str = "") -> list[dict[str, Any]]:
    """Mark the first ``prefix`` messages as a cacheable stable prefix.

    The breakpoint goes on the *last* message of the prefix, which is the
    convention OpenRouter passes through: everything up to and including it may
    be served from the provider's cache. That requires the message's content to
    be a content-part list rather than a bare string, so the string is wrapped —
    a representational change only, byte-identical on the wire as far as the
    model sees.

    ``prefix`` of 0 (or a conversation no longer than the prefix, i.e. nothing
    has been appended yet) returns the conversation untouched: there is nothing
    to save until a turn is actually being re-sent.
    """
    if prefix <= 0 or len(conversation) <= prefix or not caching_enabled(site):
        return conversation
    marked = list(conversation)
    last = dict(marked[prefix - 1])
    content = last.get("content")
    if isinstance(content, str):
        last["content"] = [{"type": "text", "text": content,
                            "cache_control": CACHE_CONTROL}]
        marked[prefix - 1] = last
    return marked


def _response_format(
    name: str = "dast_triage",
    schema: dict[str, Any] | None = None,
    description: str = "Per-alert rescan verdicts.",
) -> Any:
    from openrouter.components import ChatFormatJSONSchemaConfig, ChatJSONSchemaConfig

    return ChatFormatJSONSchemaConfig(
        type="json_schema",
        json_schema=ChatJSONSchemaConfig(
            name=name,
            description=description,
            strict=True,
            schema_=RESPONSE_SCHEMA if schema is None else schema,
        ),
    )


def api_key_from_env() -> str:
    key = os.getenv("SHARED_OPENROUTER_API_KEY", "").strip()
    if not key:
        raise LlmError(
            "SHARED_OPENROUTER_API_KEY is not set. Put it in .env (gitignored) and pass "
            "--env-file, or export it. It must never end up in a data/ artifact."
        )
    return key


class OpenRouterCorrelator:
    """One thin call per endpoint. Deliberately not batched across endpoints.

    Batching would cut request overhead but blur the unit of analysis: with one
    endpoint per call, a bad response costs one endpoint, the token count per
    endpoint is directly measurable, and the prompt stays quotable in the
    writeup.
    """

    def __init__(
        self,
        api_key: str | None = None,
        model: str = MODEL,
        temperature: float = TEMPERATURE,
        stage_max_cost_usd: float = UNLIMITED,
        run_max_cost_usd: float = UNLIMITED,
        prior_cost_usd: float = 0.0,
        max_minutes: float = UNLIMITED,
        provider: str = "",
        capabilities: "dict[str, Any] | None" = None,
    ) -> None:
        """
        :param stage_max_cost_usd: ceiling on this stage's own spend;
            :data:`UNLIMITED` (the default) means none. Enforced before each call.
        :param run_max_cost_usd: ceiling on the whole run's spend, earlier
            stages included; :data:`UNLIMITED` (the default) means none.
        :param prior_cost_usd: what earlier stages of the *same run* already
            spent, counted against ``run_max_cost_usd`` once (:func:`headroom`).
        :param max_minutes: wall-clock limit, from construction, after which no
            call starts; :data:`UNLIMITED` (the default) means none.
        :param provider: this model's provider setting — a hard pin (slug or
            comma list) that overrides the routing preference, or empty for the
            preference. Each caller (triage/synthesis/verify) resolves its own
            model's provider flag and threads it here. See :func:`build_provider`.
        :param capabilities: what the served model advertises
            (:func:`model_capabilities`); resolved from ``model`` when not given.
            Used so a call drops a sampling parameter the model cannot take
            (:func:`sampling_params`). ``None`` (catalogue unreachable, or a model
            not listed) means "unknown" — the send then behaves exactly as before.
        """
        from openrouter import OpenRouter

        self.model = model
        self.temperature = temperature
        #: The routing sent on every call, recorded in run metadata so a run is
        #: attributable to how it was routed. This correlator serves ONE model
        #: and carries that model's own provider.
        self.provider_pin = (provider or "").strip()
        self.provider_preference = build_provider(self.provider_pin)
        self._client = OpenRouter(api_key=api_key or api_key_from_env())
        #: Resolved once (not per call) so the single send site can keep
        #: temperature 0 where it is accepted and omit it where it is not — the
        #: one place model-call configuration is both uniform and frontier-safe.
        self.capabilities = (capabilities if capabilities is not None
                             else model_capabilities(model))
        timed = max_minutes is not None and max_minutes >= 0
        self.usage = LlmUsage(
            stage_max_cost_usd=stage_max_cost_usd,
            run_max_cost_usd=run_max_cost_usd,
            prior_cost_usd=prior_cost_usd,
            max_minutes=max_minutes if timed else None,
            deadline=time.monotonic() + 60 * max_minutes if timed else None,
        )

    def close(self) -> None:
        close = getattr(self._client, "close", None)
        if callable(close):
            close()

    def __enter__(self) -> "OpenRouterCorrelator":
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    def analyse(
        self,
        bundle: Bundle,
        findings_for_bundle: list[tuple[str, AlertGroup]],
        max_tokens: int = MAX_TOKENS,
        cross_endpoint: dict[str, Any] | None = None,
        system_prompt: str | None = None,
        assembler: "evidence.Assembler | None" = None,
        retrieval: "retrieval_mod.RetrievalSession | None" = None,
        retrieval_tools: "list[dict[str, Any]] | None" = None,
        max_retrievals: int = retrieval_mod.DEFAULT_MAX_CALLS,
        oracle: "dict[str, Any] | None" = None,
    ) -> dict[str, Any]:
        """Pass 1: triage one endpoint's alerts.

        :param retrieval: in ``TRIAGE_RETRIEVAL=pull``, this call's own session to the
            context server. ``None`` is push mode and the unchanged baseline.
        :param oracle: the target's documented vulnerabilities, in oracle-guided
            (``--ceiling``) runs only. ``None`` is the blind default and the
            only mode whose numbers are a detection rate.
        """
        return self.complete(
            build_messages(bundle, findings_for_bundle, cross_endpoint,
                           system_prompt, assembler, oracle),
            schema_name="dast_triage",
            schema=verdicts_schema(len(findings_for_bundle)),
            schema_description=(
                "Per-alert rescan verdicts. Cross-endpoint synthesis is a "
                "separate pass."
            ),
            require_non_empty="alert_verdicts",
            max_tokens=max_tokens,
            pass_name="screening",
            label=bundle.identifier,
            # The system prompt is byte-identical across every pass-1 call, so
            # it is a stable prefix worth marking. Applied HERE rather than in
            # `build_messages` so the recorded prompt stays a plain string: the
            # artifact should say what was asked, not how it was billed.
            #
            # Pass 1 shares only this small header across calls, so marking it gains
            # little (synthesis caches heavily only because it re-sends one large
            # identical prompt).
            # Marking it cannot hurt and may lift that; it is not where the
            # money is either way (see `cached_tokens`).
            cache_prefix=1,
            cache_site="screening",
            retrieval=retrieval,
            retrieval_tools=retrieval_tools,
            max_retrievals=max_retrievals,
        )

    @staticmethod
    def _provider_error_detail(exc: Exception) -> str:
        """The upstream provider's own error text, when the SDK wrapped it.

        An OpenRouter error can come back as a body ``{"error": {"code",
        "message"}}`` with no ``choices``; the SDK then raises a
        ``ResponseValidationError`` whose ``str()`` is its own generic
        "Response validation failed…", and the provider's real message — an
        overflow notice, a rate limit, a fault — survives ONLY on ``exc.body``.
        Read nowhere, every marker classifier below matches the wrapper's prose,
        misses, and the error escapes unclassified to take the stage down (the
        Cacti synthesis overflow crash).

        Returns the message (plus code / raw metadata when present), or ``""``
        for any exception that carries no such body. Never raises — provenance
        is never worth a second failure.
        """
        raw = getattr(exc, "body", None)
        if not raw:
            raw = getattr(getattr(exc, "raw_response", None), "text", None)
        if not isinstance(raw, str) or not raw:
            return ""
        try:
            err = json.loads(raw).get("error", {})
        except Exception:
            return raw
        if not isinstance(err, dict):
            return raw
        meta = err.get("metadata")
        parts = [str(err.get("message", "")), str(err.get("code", ""))]
        if isinstance(meta, dict):
            parts.append(str(meta.get("raw", "")))
        return " ".join(p for p in parts if p) or raw

    @staticmethod
    def _classify_text(exc: Exception) -> str:
        """``str(exc)`` plus any upstream provider body, lowercased.

        The single text every marker-based classifier matches against, so an
        SDK-wrapped error is judged by the provider's real message and not by
        the wrapper's prose. Bit-identical to ``str(exc).lower()`` for an
        exception that carries no body, so no un-wrapped failure changes class.
        """
        detail = OpenRouterCorrelator._provider_error_detail(exc)
        return (f"{exc} {detail}" if detail else str(exc)).lower()

    @staticmethod
    def _is_transient(exc: Exception) -> bool:
        """Whether this failure is worth waiting out rather than giving up on."""
        text = OpenRouterCorrelator._classify_text(exc)
        return any(marker in text for marker in TRANSIENT_MARKERS)

    @staticmethod
    def _is_context_overflow(exc: Exception) -> bool:
        """Whether the prompt overran the model's input context window."""
        text = OpenRouterCorrelator._classify_text(exc)
        return any(marker in text for marker in CONTEXT_OVERFLOW_MARKERS)

    @staticmethod
    def _is_timeout(exc: Exception) -> bool:
        """Whether a bounded request deadline fired — the provider accepted the
        request and then stalled. Consulted ONLY when a timeout was set (the
        synthesis call), so a transient 'timed out' at an un-timed stage keeps
        going through the transient path it always did."""
        try:
            import httpx
            if isinstance(exc, httpx.TimeoutException):
                return True
        except Exception:
            pass
        text = OpenRouterCorrelator._classify_text(exc)
        return "timed out" in text or "timeout" in text or "deadline" in text

    @staticmethod
    def _routing_hint(exc: Exception) -> str | None:
        """Turn OpenRouter's 404 into something the user can act on.

        "No endpoints available matching your guardrail restrictions and data
        policy" means the account's privacy settings exclude every provider that
        serves the requested model — not that the model does not exist. Models
        served by a single provider (Alibaba for the qwen-plus snapshots) fail
        this way while multi-provider models on the same account succeed.
        """
        text = f"{exc} {OpenRouterCorrelator._provider_error_detail(exc)}"
        if "No endpoints available" not in text and "data policy" not in text:
            return None
        return (
            "OpenRouter has no provider for this model that your account's "
            "privacy settings allow.\n"
            "  Either allow the provider at https://openrouter.ai/settings/privacy,\n"
            "  or choose a model served by several providers — single-provider "
            "models fail this way\n"
            "  while multi-provider ones on the same account succeed."
        )

    def complete(
        self,
        messages: list[dict[str, str]],
        schema_name: str,
        schema: dict[str, Any],
        schema_description: str,
        require_non_empty: str | None = None,
        max_tokens: int = MAX_TOKENS,
        pass_name: str = "screening",
        label: str = "",
        retrieval: "retrieval_mod.RetrievalSession | None" = None,
        retrieval_tools: "list[dict[str, Any]] | None" = None,
        max_retrievals: int = retrieval_mod.DEFAULT_MAX_CALLS,
        cache_prefix: int = 0,
        cache_site: str = "",
        timeout: float | None = None,
    ) -> dict[str, Any]:
        """One structured-output call, retried once on a malformed response.

        Refuses before it spends anything once the arm's cost ceiling is
        reached, raising :class:`LlmError` with kind ``budget``. That degrades
        into the same asked-but-unanswered state a failed call produces, which
        is the honest outcome: the findings were put to the model and it never
        answered, and the artifact must not imply they were judged.

        The retry is worth its cost because the observed failures are not
        deterministic — the same prompt that returns an empty message can
        succeed on a second attempt — and at this model's prices a whole run is
        about two cents, so losing the call is far more expensive than re-asking.

        Shared by both passes so the failure accounting, the fence stripping and
        the empty-answer detection cannot drift apart between them.

        **Retrieval (``TRIAGE_RETRIEVAL=pull``).** Given a ``retrieval`` session and the
        ``retrieval_tools`` it declares, this becomes a tool-use loop: a response
        carrying tool calls is not an answer, so the calls are executed against
        the read-only context server, appended as ``tool`` turns, and the model
        is asked again. Three properties make the loop safe to run inside a
        concurrent pass:

        * **It is bounded by ``max_retrievals``.** Every call the model issues
          spends one, whatever it returns — a malformed argument list costs
          budget too, or a model that cannot form a call would loop forever.
        * **The tools are withdrawn once the budget is spent**, and the spike
          established that a tool-less turn still answers in schema. So the loop
          ends by the model *answering*, not by an error.
        * **A tool call on a turn where no tools were declared is a protocol
          violation**, raised as ``tool_loop`` rather than answered — otherwise
          a provider that ignores the withdrawal would spin.

        With ``retrieval`` unset this method is bit-identical to what it was,
        which is what makes ``TRIAGE_RETRIEVAL=push`` a baseline rather than a
        near-baseline.

        **Prompt caching (``cache_prefix``).** Both multi-turn callers — the pull
        retrieval loop here and the verification loop — re-send the whole
        conversation on every turn, which is why pull spends far more prompt tokens
        for the same work. The re-sent part is a *stable prefix*: the system prompt
        and the original
        task block never change, only the newest tool output is new.
        ``cache_prefix`` is how many leading messages form that prefix, and the
        last of them is marked as a cache breakpoint, so a provider that supports
        caching bills the prefix at the cached rate and only the new turn at
        full price. Caching is the one lever that attacks the re-send at all;
        marking the breakpoint is all this side can do, and whether it pays is
        then a *measurement* (the pull-vs-push A/B) rather than an assumption.

        It cannot change an answer: a cached prefix is byte-identical to the one
        that would otherwise be sent, and a provider that does not support the
        field ignores it. So ``cache_prefix=0`` — every single-turn caller —
        leaves this method exactly as it was.
        """
        # Before anything is spent: a ceiling on what a run *may* cost is only a
        # ceiling if it is checked ahead of the call, not after it.
        if self.usage.budget_exhausted():
            raise LlmError(self.usage.budget_note(), "budget")
        if self.usage.out_of_time():
            raise LlmError(self.usage.time_note(), "time_limit")

        # Two independent retry budgets, because the two failures are nothing
        # alike: a *malformed answer* is the model having a bad turn (one more
        # call is worth it), while a *transient transport error* is the network
        # or a rate limit (worth waiting out, several times, with backoff).
        # Truncation is neither — it will truncate again at the same ceiling, so
        # the caller splits the chunk instead.
        parse_retries_left = 1
        transient_retries_left = MAX_TRANSIENT_ATTEMPTS - 1
        # A copy: the retrieval turns accumulate here, and the caller's list has
        # to stay the prompt it built — `_triage_bundle` reuses a chunk when it
        # re-asks for missing verdicts.
        conversation: list[dict[str, Any]] = _mark_cache_prefix(
            list(messages), cache_prefix, cache_site)
        pulling = retrieval is not None and bool(retrieval_tools)
        retrievals_left = max(0, int(max_retrievals)) if pulling else 0
        while True:
            declared = retrievals_left > 0
            started = time.monotonic()
            try:
                result = self._client.chat.send(
                    model=self.model,
                    messages=conversation,
                    # temperature (0) + seed, dropped when the served model is
                    # known not to accept them (frontier compatibility). `getattr`
                    # covers the test clients built via `__new__`, which set no
                    # capabilities attribute — there it is `None` (unknown) and
                    # both are sent, as before. See sampling_params.
                    **sampling_params(self.temperature,
                                      getattr(self, "capabilities", None)),
                    max_tokens=max_tokens,
                    response_format=_response_format(
                        schema_name, schema, schema_description
                    ),
                    # Provider routing, uniform across every stage and model —
                    # a throughput/require-parameters preference by default, or a
                    # hard pin when OPENROUTER_PROVIDER / --provider is set. See
                    # build_provider.
                    provider=self.provider_preference,
                    tools=retrieval_tools if declared else None,
                    # Opt-in: without it the response carries no routing block,
                    # and every call logs provider/region as null.
                    x_open_router_metadata="enabled",
                    # A bounded wall-clock deadline for THIS call. Synthesis passes
                    # a value (its whole-corpus call is the one that stalls);
                    # screening/verify pass None, which the SDK reads as its own
                    # default — so their behaviour is unchanged. A provider that
                    # accepts the request and never answers is abandoned here
                    # rather than hanging the run, and the `except` below turns the
                    # resulting timeout into a classifiable, non-transient failure.
                    timeout_ms=(int(timeout * 1000)
                                if (timeout and timeout > 0) else None),
                    stream=False,
                )
            except Exception as exc:
                hint = self._routing_hint(exc)
                if hint is not None:
                    raise LlmError(f"{exc}\n  {hint}", "no_provider") from exc
                # A prompt over the context window is a clean, classifiable
                # failure the caller can degrade on — not a raw provider error to
                # crash the run with, and never worth retrying unchanged.
                if self._is_context_overflow(exc):
                    raise LlmError(
                        f"the prompt exceeded the model's context window ({exc})",
                        "context_overflow",
                    ) from exc
                # A deadline WE set (synthesis) fired. It must NOT fall through to
                # the transient path: "timeout" is a TRANSIENT_MARKER, so a hang
                # would be retried up to MAX_TRANSIENT_ATTEMPTS — each attempt
                # waiting out the same stall — and the raw httpx error would then
                # escape past the synthesis arm's `except LlmError` and take the
                # whole triage stage down (the >182 min Cacti hang, exit 1). As a
                # classifiable, non-transient LlmError the caller degrades to
                # "no synthesis this run" and the chain continues to verify.
                if timeout and self._is_timeout(exc):
                    raise LlmError(
                        f"the synthesis call exceeded its {timeout:.0f}s "
                        f"deadline ({exc})",
                        "timeout",
                    ) from exc
                if self._is_transient(exc) and transient_retries_left:
                    attempt = MAX_TRANSIENT_ATTEMPTS - transient_retries_left
                    transient_retries_left -= 1
                    self.usage.note_retry()
                    # Jittered, so several workers that tripped the same ceiling
                    # do not all come back at the same instant and trip it again.
                    # Timing only — backoff cannot change a verdict.
                    delay = TRANSIENT_BACKOFF_SECONDS * (2 ** (attempt - 1))
                    time.sleep(delay + random.uniform(0, delay / 2))
                    continue
                # An error none of the branches above could classify. For the
                # synthesis call — the ONLY caller that sets ``timeout`` — it
                # must DEGRADE, not escape: the whole-corpus pass is one call,
                # and a raw provider error (an OpenRouter error-body the SDK
                # could not parse into a completion — ``ResponseValidationError``
                # — or a provider fault with no classifiable status) would
                # otherwise sail past the synthesis arm's ``except LlmError`` and
                # take the whole triage stage down, exactly as the context-
                # overflow crash and the >182 min stall did. As a classifiable
                # ``provider_error`` the arm narrows once, then degrades to "no
                # synthesis this run" and the chain continues to verify. Every
                # other caller (``timeout`` None) still raises, so a hard failure
                # in pass 1 or verify is surfaced, not silently swallowed.
                if timeout:
                    detail = self._provider_error_detail(exc)
                    note = f" ({detail[:MAX_FAILURE_DETAIL_CHARS]})" if detail else ""
                    raise LlmError(
                        f"the synthesis call failed with an unclassified "
                        f"provider error{note}: {exc}",
                        "provider_error",
                    ) from exc
                raise

            latency_ms = (time.monotonic() - started) * 1000
            # Every served turn's tokens are counted, retrieval turns included:
            # what pull mode costs is the sum of them, and counting only the
            # final answer would report the arm as cheaper than it is.
            self.usage.record_tokens(getattr(result, "usage", None))

            calls = self._tool_calls(result) if pulling else []
            if calls:
                if not declared:
                    self.usage.record_call(
                        pass_name=pass_name, label=label,
                        model_requested=self.model, latency_ms=latency_ms,
                        result=result, outcome="tool_loop",
                    )
                    raise LlmError(
                        "the model asked for a retrieval on a turn where no "
                        "tools were declared — its retrieval budget was already "
                        "spent",
                        "tool_loop",
                    )
                self.usage.record_call(
                    pass_name=pass_name, label=label, model_requested=self.model,
                    latency_ms=latency_ms, result=result, outcome="tool_calls",
                )
                message = (getattr(result, "choices", None) or [])[0].message
                if len(conversation) == len(messages):
                    # The first tool turn is where the conversation stops being
                    # the prompt and starts growing: from here every turn
                    # re-sends these same leading messages, so this is the point
                    # at which marking them as a cache prefix begins to pay.
                    conversation = _mark_cache_prefix(conversation, len(messages),
                                                     "retrieval")
                conversation.append(retrieval_mod.assistant_turn(message, calls))
                for call in calls:
                    retrievals_left -= 1
                    conversation.append(
                        retrieval_mod.tool_turn(call, self._retrieve(retrieval, call))
                    )
                continue

            try:
                parsed = self._parse(result, require_non_empty, max_tokens)
            except LlmError as exc:
                self.usage.record_call(
                    pass_name=pass_name, label=label, model_requested=self.model,
                    latency_ms=latency_ms, result=result, outcome=exc.kind,
                )
                if exc.kind == "truncated" or not parse_retries_left:
                    raise
                parse_retries_left -= 1
                self.usage.note_retry()
                # The retry drops the tools: malformed answers arrive on turns where
                # tools are still declared, and by the retry the model has shown it
                # wants to answer rather than pull again. Withdrawing them puts the
                # retry in a known-good shape — a tool-less
                # turn that must answer in schema — instead of re-asking the
                # question that just failed.
                retrievals_left = 0
                continue
            self.usage.record_call(
                pass_name=pass_name, label=label, model_requested=self.model,
                latency_ms=latency_ms, result=result, outcome="ok",
            )
            return parsed

    @staticmethod
    def _tool_calls(result: Any) -> list[dict[str, Any]]:
        """The retrieval requests on this response, if it is asking rather than answering."""
        choices = getattr(result, "choices", None) or []
        if not choices:
            return []
        return retrieval_mod.parse_tool_calls(choices[0].message)

    @staticmethod
    def _retrieve(retrieval: "retrieval_mod.RetrievalSession",
                  call: dict[str, Any]) -> str:
        """Answer one of the model's retrieval requests, well-formed or not.

        A call whose arguments did not parse is answered with the parse failure
        rather than executed, so the model can correct itself on the next turn —
        and it still costs budget, because a model that cannot form a call would
        otherwise loop for free.
        """
        if call["error"]:
            return retrieval_mod.refusal(call["error"])
        return retrieval.call(call["name"], call["arguments"])

    def _parse(
        self,
        result: Any,
        require_non_empty: str | None = None,
        max_tokens: int = MAX_TOKENS,
    ) -> dict[str, Any]:
        """The final answer, parsed. Tokens are counted by the caller.

        Counting them here would miss a retrieval turn, which never reaches this
        method — see :meth:`complete`.
        """
        choices = getattr(result, "choices", None) or []
        if not choices:
            raise LlmError("model returned no choices", "no_choices")
        choice = choices[0]
        message = choice.message
        finish_reason = str(getattr(choice, "finish_reason", "") or "")

        content = getattr(message, "content", None)
        if isinstance(content, list):  # some providers return content parts
            content = "".join(getattr(part, "text", "") or "" for part in content)

        if finish_reason == "length":
            raise LlmError(
                f"response hit the {max_tokens}-token ceiling and was truncated",
                "truncated",
            )
        if not content:
            # This model reasons before answering, and reasoning tokens come out
            # of the same completion budget. An empty content field with a
            # populated reasoning field means it thought and never concluded.
            reasoned = bool(getattr(message, "reasoning", None))
            raise LlmError(
                "model returned an empty message"
                + (" (reasoning present but no answer)" if reasoned else ""),
                "empty_reasoning_only" if reasoned else "empty",
            )

        try:
            parsed = json.loads(_strip_code_fence(content))
        except json.JSONDecodeError as exc:
            raise LlmError(
                f"model output was not JSON: {content[:200]!r}", "not_json"
            ) from exc
        # Valid JSON that is not an *object* — a bare array of verdicts is the
        # observed shape — used to reach the caller as a raw AttributeError from
        # `.get`, which the worker reported as `worker_error` and which no retry
        # path could see. It is the same failure as unparseable output: the model
        # did not answer in the schema, so it is re-asked.
        if not isinstance(parsed, dict):
            raise LlmError(
                f"model returned JSON that is not an object: "
                f"{type(parsed).__name__}, {content[:200]!r}",
                "not_json",
            )

        # Well-formed JSON carrying no verdicts is the quietest way to lose a
        # whole chunk: it parses, it validates, and every alert in the call ends
        # up unanswered with nothing logged. Every call is made with at least
        # one alert, so an empty list is always a failure to follow the
        # instruction, never a legitimate answer — raise so the retry fires.
        if require_non_empty and not parsed.get(require_non_empty):
            raise LlmError(
                f"model returned valid JSON with an empty {require_non_empty} list",
                "no_verdicts",
            )
        return parsed


# -- merging the model's output back into the findings ---------------------


def merge_verdicts(
    findings: list[dict[str, Any]],
    response: dict[str, Any],
    bundle_finding_ids: Iterable[str],
    had_source: bool = False,
) -> tuple[int, list[str]]:
    """Write the model's verdicts onto the matching findings.

    Returns (applied, unknown_ids). A verdict for a finding_id that was not in
    the prompt is dropped rather than trusted: it is a hallucinated identifier,
    and the count of them is worth reporting.

    :param had_source: whether the prompt held this endpoint's handler source;
        recorded on each verdict, since a citation means nothing without it.
    """
    by_id = {f["finding_id"]: f for f in findings}
    allowed = set(bundle_finding_ids)
    applied = 0
    unknown: list[str] = []
    for verdict in response.get("alert_verdicts", []):
        fid = verdict.get("finding_id", "")
        if fid not in allowed or fid not in by_id:
            unknown.append(fid)
            continue
        finding = by_id[fid]
        finding["llm"] = {
            "needs_rescan": bool(verdict.get("needs_rescan")),
            "verdict": verdict.get("verdict", ""),
            "confidence": verdict.get("confidence", ""),
            "reasoning": verdict.get("reasoning", ""),
            "suggested_tool": verdict.get("suggested_tool", "none"),
            "had_source": had_source,
        }
        finding["agreement"] = join.label_agreement(finding)
        applied += 1
    return applied, unknown


#: OpenRouter's public model catalogue. No API key, so a run can record what the
#: model it used actually supports without touching the credential.
#: The two shapes in which OpenRouter marks an id as an explicit **moving
#: target**, and therefore the two this project refuses outright:
#:
#: * a ``~`` prefix — ``~deepseek/deepseek-v4-flash-latest``;
#: * a ``-latest`` suffix.
#:
#: The invariant behind the refusal is the one axis the thesis cannot afford to
#: lose: a re-run whose weights moved underneath it is not a reproduction.
FLOATING_ALIAS_PREFIX = "~"
FLOATING_ALIAS_SUFFIX = "-latest"

#: Model ids in use here that carry **no date** and are nonetheless pinned,
#: with the date the OpenRouter catalogue was checked to establish it. Shape
#: cannot settle these — see :func:`is_pinned` — so the evidence is recorded
#: instead of re-derived, and re-checking one is a matter of looking up the id
#: in the list rather than reasoning about its name.
#:
#: Established against the OpenRouter catalogue: each model is its own entry, and a
#: version bump mints a NEW id rather than replacing one in place (``minimax-m2.5``,
#: ``m2.7`` and ``m3`` coexist, as do ``deepseek-v3.2`` and ``deepseek-v3.2-exp``).
#: Neither has a dated snapshot to
#: pin to: the version tag is the finest granularity offered.
CATALOGUE_CHECKED = {
    "deepseek/deepseek-v3.2": "2026-09-02",
    "minimax/minimax-m2.5": "2026-09-02",
}


def is_pinned(model_id: str) -> bool:
    """Whether this id is *known* to name one fixed set of weights.

    Deliberately narrow, because shape alone cannot decide the interesting case.
    ``deepseek/deepseek-v4-flash`` and ``deepseek/deepseek-v4-flash-0731`` are
    both well-formed version-bearing ids, and only the catalogue says the first
    follows the family while the second is a snapshot. A regex confident enough
    to separate them would be confidently wrong on the next naming convention.

    So this refuses the two shapes that are unambiguous
    (:data:`FLOATING_ALIAS_PREFIX`, :data:`FLOATING_ALIAS_SUFFIX`) and otherwise
    accepts an id only if it carries a date-like snapshot suffix **or** appears
    in :data:`CATALOGUE_CHECKED`. Adding a new undated model is therefore a
    deliberate act with a recorded check behind it, which is exactly the point:
    the invariant stops being a convention someone has to remember.
    """
    model_id = (model_id or "").strip()
    if not model_id or model_id.startswith(FLOATING_ALIAS_PREFIX):
        return False
    name = model_id.split("/", 1)[-1]
    if name.endswith(FLOATING_ALIAS_SUFFIX):
        return False
    if model_id in CATALOGUE_CHECKED:
        return True
    # A date at the end, in the three shapes this catalogue's providers use for a
    # snapshot: four-digit MMDD (`-0731`), eight-digit ISO (`-20251001`), and dashed
    # ISO (`-2025-07-28`, e.g. `qwen/qwen-plus-2025-07-28`).
    return bool(_re.search(r"-(?:\d{4}|\d{8}|\d{4}-\d{2}-\d{2})$", name))


MODELS_API_URL = "https://openrouter.ai/api/v1/models"


def model_capabilities(model: str, timeout: float = 10.0) -> dict[str, Any] | None:
    """What the served model advertises, or ``None`` if the catalogue is unreachable.

    Recorded next to the *requested* parameters because the two can disagree
    silently: OpenRouter forwards ``seed`` only to providers that accept it and
    drops it elsewhere, so an artifact that lists a seed without saying whether
    the model honours it claims a determinism the run may not have had. Same for
    ``structured_outputs`` — a model advertising only ``response_format`` may
    ignore a strict JSON schema and answer in prose, which this pipeline counts
    as a parse failure rather than a model opinion.

    ``None`` (not ``False``) when the catalogue could not be read: a missing
    measurement and a measured "no" must stay distinguishable.
    """
    try:
        import httpx

        response = httpx.get(MODELS_API_URL, timeout=timeout)
        response.raise_for_status()
        entry = next(
            (m for m in response.json().get("data", []) if m.get("id") == model), None
        )
    except Exception:  # network, shape, anything — provenance is never fatal
        return None
    if entry is None:
        return None
    supported = set(entry.get("supported_parameters") or [])
    return {
        "seed": "seed" in supported,
        "temperature": "temperature" in supported,
        "structured_outputs": "structured_outputs" in supported,
        "response_format": "response_format" in supported,
        "context_length": entry.get("context_length"),
        "pricing": entry.get("pricing"),
    }


def run_metadata(model: str, usage: LlmUsage, candidates: int,
                 concurrency: int = 1,
                 pass1_context: str = DEFAULT_PASS1_CONTEXT,
                 prompt: "prompts.Prompt | None" = None,
                 provider: "dict[str, Any] | None" = None) -> dict[str, Any]:
    """The `llm` block of the artifact: everything needed to rerun the pass.

    :param concurrency: how many calls were in flight at once. Recorded because
        it is the difference between the per-call latencies below and the stage's
        wall time — without it the two look contradictory.
    :param pass1_context: how much each call was told about the endpoints it was
        not shown (:data:`PASS1_CONTEXT_LEVELS`). Recorded next to the prompt
        version because it changes what the prompt *contained* without changing
        the prompt itself: two runs that differ here are not comparable on
        self-consistency, which is the whole point of being able to differ.
    :param prompt: the prompt file this run actually used. Its verbatim text,
        name and version go into the artifact, so a run stays readable after the
        file is edited or deleted.
    """
    prompt = prompt or prompts.load("screening")
    capabilities = model_capabilities(model)
    return {
        "model": model,
        "temperature": TEMPERATURE,
        "seed": SEED,
        # What the model says it can do, so `seed: 20260817` above is never read
        # as "this run was deterministic" when the model never accepted a seed.
        "model_capabilities": capabilities,
        "seed_supported": None if capabilities is None else capabilities["seed"],
        "temperature_supported": (None if capabilities is None
                                  else capabilities.get("temperature")),
        "max_tokens": MAX_TOKENS,
        **prompt.as_metadata(),
        "response_schema": RESPONSE_SCHEMA,
        "candidate_bundles": candidates,
        "concurrency": concurrency,
        "pass1_context": pass1_context,
        # How the run asked OpenRouter to route — the preference, or a hard pin —
        # so a run is attributable to its routing, not only to which providers
        # happened to answer (recorded per call in `usage`).
        "provider_preference": provider,
        "usage": usage.as_dict(),
    }
