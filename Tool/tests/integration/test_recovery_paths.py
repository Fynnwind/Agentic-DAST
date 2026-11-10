"""Tests for the failure-recovery paths, driven by fake clients.

Every branch here was written in response to a *live* run losing data, and none
of them had ever executed under test — which is precisely how they shipped
broken twice. They are exercised end to end through `run_llm_arm` and
`run_synthesis_arm` with a stubbed OpenRouter client, so the queue logic, the
ceiling escalation and the corpus narrowing are all covered offline.
"""

from __future__ import annotations

import json
from pathlib import Path

#: Shared fixture corpus, one level up now that tests are grouped by kind.
FIXTURES_DIR = Path(__file__).resolve().parents[1] / "fixtures"

import pytest

from dast_orchestrator.analysis import join
from dast_orchestrator.analysis import screening
from dast_orchestrator.analysis import synthesize
from dast_orchestrator.stages import triage
from dast_orchestrator.analysis.join import RunArtifacts
from dast_orchestrator.analysis.screening import LlmError, LlmUsage
from dast_orchestrator.adapters.noir_runner import (
    build_ai_context_artifact,
    build_seed_map_artifact,
    parse_endpoints,
)

FIXTURES = FIXTURES_DIR


@pytest.fixture
def run() -> RunArtifacts:
    endpoints = parse_endpoints(
        json.loads((FIXTURES / "noir-gitea-sample.json").read_text())
    )
    return RunArtifacts(
        timestamp="20260817T155107Z",
        ai_context=build_ai_context_artifact(endpoints, Path("/src"), "20260817T155107Z"),
        zap_report=json.loads((FIXTURES / "zap-alerts-sample.json").read_text()),
        seed_map=build_seed_map_artifact(
            endpoints, "http://target-gitea:3000", "20260817T155107Z"
        ),
        ai_context_path=Path("a.json"),
        zap_report_path=Path("b.json"),
        seed_map_path=Path("c.json"),
    )


@pytest.fixture
def bundles(run):
    return join.build_bundles(run)


@pytest.fixture
def findings(bundles):
    return join.build_findings(bundles)


class _FakeClient:
    """Stands in for OpenRouterCorrelator, scripted per test."""

    def __init__(self, *, truncate_until: int = 0, truncate_synthesis_once: bool = False,
                 overflow_synthesis_once: bool = False, timeout_synthesis: bool = False):
        self.usage = LlmUsage()
        self.provider_pin = ""
        self.provider_preference = screening.build_provider("")
        self.capabilities = {"seed": True, "temperature": True,
                             "structured_outputs": True}
        self.truncate_until = truncate_until
        self.truncate_synthesis_once = truncate_synthesis_once
        self.overflow_synthesis_once = overflow_synthesis_once
        self.timeout_synthesis = timeout_synthesis
        self.analyse_calls: list[tuple[int, int]] = []   # (chunk size, ceiling)
        self.synthesis_calls: list[int] = []             # endpoints in corpus

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        return None

    def analyse(self, bundle, chunk, max_tokens=screening.MAX_TOKENS,
                cross_endpoint=None, system_prompt=None, assembler=None,
                retrieval=None, retrieval_tools=None, max_retrievals=0,
                oracle=None):
        self.analyse_calls.append((len(chunk), max_tokens))
        if max_tokens < self.truncate_until:
            raise LlmError("truncated", "truncated")
        return {
            "alert_verdicts": [
                {
                    "finding_id": fid,
                    "needs_rescan": False,
                    "verdict": "likely-false-positive",
                    "confidence": "low",
                    "reasoning": "stub",
                    "suggested_tool": "none",
                }
                for fid, _ in chunk
            ]
        }

    def complete(self, messages, **kwargs):
        corpus = json.loads(messages[1]["content"])
        self.synthesis_calls.append(len(corpus["endpoints"]))
        if self.truncate_synthesis_once and len(self.synthesis_calls) == 1:
            raise LlmError("truncated", "truncated")
        if self.overflow_synthesis_once and len(self.synthesis_calls) == 1:
            raise LlmError("prompt exceeded the context window", "context_overflow")
        if self.timeout_synthesis and len(self.synthesis_calls) == 1:
            raise LlmError("the synthesis call exceeded its 300s deadline", "timeout")
        return {"correlated_findings": []}


# -- the 1-alert truncation that cost the qwen run two findings ------------


def test_an_unsplittable_chunk_is_retried_with_a_bigger_ceiling(
    monkeypatch, bundles, findings
):
    # qwen3-235b truncated on chunks of ONE alert. Halving cannot help, so the
    # only lever is more room — without it the finding is simply lost.
    client = _FakeClient(truncate_until=screening.RETRY_MAX_TOKENS)
    monkeypatch.setattr(
        screening, "OpenRouterCorrelator", lambda **_kw: client
    )
    monkeypatch.setattr(screening, "MAX_ALERTS_PER_CALL", 1)

    triage.run_llm_arm(bundles, findings, "stub-model", 0)

    ceilings = [ceiling for _, ceiling in client.analyse_calls]
    assert screening.MAX_TOKENS in ceilings
    assert screening.RETRY_MAX_TOKENS in ceilings, "never escalated the ceiling"
    # And the retry actually produced verdicts rather than a recorded failure.
    assert any(f.get("llm") for f in findings)
    assert client.usage.failures == 0


def test_a_multi_alert_chunk_is_split_before_the_ceiling_is_raised(
    monkeypatch, bundles, findings
):
    # Splitting is cheaper than a bigger budget, so it must be tried first.
    client = _FakeClient(truncate_until=screening.MAX_TOKENS + 1)
    monkeypatch.setattr(screening, "OpenRouterCorrelator", lambda **_kw: client)

    triage.run_llm_arm(bundles, findings, "stub-model", 0)

    sizes = [size for size, _ in client.analyse_calls]
    assert any(size == 1 for size in sizes), "never split down to a single alert"
    assert client.usage.splits > 0


# -- the synthesis truncation that cost a whole pass -----------------------


def test_synthesis_retries_with_a_narrower_corpus_after_truncating(
    monkeypatch, bundles, findings
):
    client = _FakeClient(truncate_synthesis_once=True)
    monkeypatch.setattr(screening, "OpenRouterCorrelator", lambda **_kw: client)

    summary = join.summarise(bundles, findings, [])
    # repeats=1 explicitly: the subject here is the narrowing retry, and letting
    # it inherit the sampling default would make the call count measure both.
    _, metadata = triage.run_synthesis_arm(
        bundles, findings, summary, "stub-model", repeats=1)

    assert len(client.synthesis_calls) == 2, "did not retry after truncation"
    assert client.synthesis_calls[1] <= client.synthesis_calls[0]
    # A recovered pass must not still be reported as failed.
    assert metadata["failed"] is None


def test_synthesis_over_the_context_window_narrows_then_recovers(
    monkeypatch, bundles, findings
):
    # A whole-corpus pass on a large target can exceed the model's input window.
    # Its one lever is the same as a truncation's — fewer endpoints — so it must
    # narrow and retry rather than crash the run (Cacti, 342 endpoints).
    client = _FakeClient(overflow_synthesis_once=True)
    monkeypatch.setattr(screening, "OpenRouterCorrelator", lambda **_kw: client)

    summary = join.summarise(bundles, findings, [])
    _, metadata = triage.run_synthesis_arm(
        bundles, findings, summary, "stub-model", repeats=1)

    assert len(client.synthesis_calls) == 2, "did not retry after overflow"
    assert client.synthesis_calls[1] <= client.synthesis_calls[0]
    assert metadata["failed"] is None
    # The event is countable even when the retry recovers.
    assert client.usage.failure_kinds.get("context_overflow") == 1


def test_synthesis_timeout_is_skipped_and_recorded_without_retrying(
    monkeypatch, bundles, findings
):
    # A provider that accepts the whole-corpus request and then stalls is the
    # failure a bounded deadline turns into a `timeout`. Unlike a truncation or an
    # overflow it must NOT narrow-and-retry (that only waits out the same stall):
    # the pass is skipped, recorded, and the chain continues on pass-1 verdicts.
    client = _FakeClient(timeout_synthesis=True)
    monkeypatch.setattr(screening, "OpenRouterCorrelator", lambda **_kw: client)

    summary = join.summarise(bundles, findings, [])
    correlated, metadata = triage.run_synthesis_arm(
        bundles, findings, summary, "stub-model", repeats=1)

    assert len(client.synthesis_calls) == 1, "a timeout must skip, not retry"
    assert correlated == []
    # Degraded, not crashed: run_synthesis_arm returned rather than raising, so
    # the driver does not `return 1` and verify still runs.
    assert metadata["failed"] is not None
    # And the skip is a distinct, countable event in the triage metrics.
    assert client.usage.failure_kinds.get("timeout") == 1


def test_synthesis_over_the_prompt_cap_is_skipped_without_attempting(
    monkeypatch, bundles, findings
):
    # With a prompt-token cap below the corpus, pass 2 is NOT attempted: no model
    # call at all (discovery or repeats), a distinct `oversize` record, and the
    # chain continues on pass-1 verdicts. This is the operator opting out by size,
    # separate from a `timeout` (a call made and then abandoned).
    client = _FakeClient()
    monkeypatch.setattr(screening, "OpenRouterCorrelator", lambda **_kw: client)

    summary = join.summarise(bundles, findings, [])
    correlated, metadata = triage.run_synthesis_arm(
        bundles, findings, summary, "stub-model", repeats=3, max_prompt_tokens=1)

    assert client.synthesis_calls == [], "a capped corpus must not call the model"
    assert correlated == []
    assert metadata["failed"] is not None
    assert client.usage.failure_kinds.get("oversize") == 1


def test_synthesis_uses_its_own_larger_ceiling(monkeypatch, bundles, findings):
    seen: dict = {}

    class _Recorder(_FakeClient):
        def complete(self, messages, **kwargs):
            seen.update(kwargs)
            return super().complete(messages, **kwargs)

    monkeypatch.setattr(screening, "OpenRouterCorrelator", lambda **_kw: _Recorder())
    summary = join.summarise(bundles, findings, [])
    triage.run_synthesis_arm(bundles, findings, summary, "stub-model")
    assert seen["max_tokens"] == synthesize.SYNTHESIS_MAX_TOKENS


# -- a short answer is re-asked, not lost ----------------------------------


class _ShortThenComplete:
    """Answers the first call short, the re-ask completely."""

    def __init__(self):
        self.usage = screening.LlmUsage()
        self.model = "m/x"
        self.calls = []

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        return None

    def analyse(self, bundle, chunk, max_tokens=screening.MAX_TOKENS,
                cross_endpoint=None, system_prompt=None, assembler=None,
                retrieval=None, retrieval_tools=None, max_retrievals=0,
                oracle=None):
        ids = [fid for fid, _ in chunk]
        self.calls.append(ids)
        answered = ids if len(self.calls) > 1 else ids[:1]
        return {"alert_verdicts": [
            {"finding_id": fid, "needs_rescan": False, "verdict": "x",
             "confidence": "low", "reasoning": "r", "suggested_tool": "none"}
            for fid in answered
        ]}


def test_a_short_answer_is_re_asked_for_exactly_what_is_missing(bundles, findings):
    # The measured failure: over a 12-run sheet the cheap model returned fewer
    # verdicts than it was asked for on 18-30% of findings while reporting
    # `failed_calls: 0` — a short-but-valid answer is not an error, so nothing
    # saw it and those findings became silently asked-but-unanswered.
    bundle = max(bundles, key=lambda b: len(triage._findings_of(b, findings)))
    pairs = triage._findings_of(bundle, findings)
    assert len(pairs) > 1, "need a multi-alert endpoint for this test"

    client = _ShortThenComplete()
    responses, _lines, calls = triage._triage_bundle(client, bundle, pairs)

    asked = [fid for fid, _ in pairs]
    assert client.calls[0] == asked                 # first call asked for all
    assert client.calls[1] == asked[1:]             # re-ask: only what was missing
    assert calls == 2

    applied = 0
    for ids, response in responses:
        merged, _ = screening.merge_verdicts(findings, response, ids)
        applied += merged
    assert applied == len(pairs), "every asked finding ends up with a verdict"


def test_a_failed_sample_costs_its_own_sample_and_nothing_else(
    monkeypatch, bundles, findings
):
    """Sampling must degrade one draw at a time, not lose the pass.

    The whole argument for repeats is that a synthesis claim is drawn from a
    distribution. A run that discarded every sample because the fourth call
    failed would be strictly worse than the single call it replaced.
    """
    client = _FakeClient(truncate_synthesis_once=True)
    monkeypatch.setattr(screening, "OpenRouterCorrelator", lambda **_kw: client)

    summary = join.summarise(bundles, findings, [])
    _, metadata = triage.run_synthesis_arm(
        bundles, findings, summary, "stub-model", repeats=3)

    # It asked for three and says how many it actually got — a missing sample
    # and a sample that found nothing must not look alike.
    assert metadata["repeats"] == 3
    assert metadata["samples_collected"] <= 3


def test_synthesis_samples_run_concurrently_and_merge_order_independently(
    monkeypatch, bundles, findings
):
    """Five sequential samples add ~4 minutes of pure waiting to every run.

    The two properties that make a pool safe here are the same ones pass 1
    relies on: workers share no state, and the merged result cannot depend on
    which sample finished first (`merge_repeats` sorts by reproducibility, then
    by the claim itself).
    """
    import threading
    import time

    client = _FakeClient()
    monkeypatch.setattr(screening, "OpenRouterCorrelator", lambda **_kw: client)

    live, peak, lock = 0, 0, threading.Lock()
    real_complete = client.complete

    def counting_complete(*a, **kw):
        nonlocal live, peak
        with lock:
            live += 1
            peak = max(peak, live)
        try:
            # A real call takes ~40-70s; the stub returns instantly, and an
            # instant call cannot overlap with anything. The sleep is what makes
            # "did these run at the same time" observable at all.
            time.sleep(0.05)
            return real_complete(*a, **kw)
        finally:
            with lock:
                live -= 1

    client.complete = counting_complete
    summary = join.summarise(bundles, findings, [])
    _, metadata = triage.run_synthesis_arm(
        bundles, findings, summary, "stub-model", repeats=5, concurrency=4)

    assert metadata["repeats"] == 5
    assert metadata["concurrency"] == 4
    # The first sample is sequential (it settles the corpus size); the other
    # four share a pool, so more than one must have been in flight at once.
    assert peak > 1, f"samples ran sequentially (peak in flight = {peak})"


def test_concurrency_one_reproduces_the_sequential_behaviour(
    monkeypatch, bundles, findings
):
    client = _FakeClient()
    monkeypatch.setattr(screening, "OpenRouterCorrelator", lambda **_kw: client)

    summary = join.summarise(bundles, findings, [])
    _, metadata = triage.run_synthesis_arm(
        bundles, findings, summary, "stub-model", repeats=3, concurrency=1)

    assert metadata["samples_collected"] == 3


# -- ensemble providers: each model pinned to its own, not one shared ------


def test_ensemble_pins_each_member_to_its_positional_provider(
    monkeypatch, bundles, findings
):
    """A single provider cannot serve models from different vendors, so an
    ensemble matches --synthesis-providers to --synthesis-models by position;
    a member with no slot falls back to the single --synthesis-provider.
    """
    seen: dict[str, str] = {}   # model -> the provider its client was built with

    class _Rec:
        def __init__(self, *, api_key=None, model="", provider="", **_kw):
            self.model = model
            seen[model] = provider
            self.usage = LlmUsage()
            self.provider_pin = provider
            self.provider_preference = screening.build_provider(provider)

        def __enter__(self):
            return self

        def __exit__(self, *_exc):
            return None

        def complete(self, messages, **_kw):
            return {"correlated_findings": []}

    monkeypatch.setattr(screening, "OpenRouterCorrelator", _Rec)
    summary = join.summarise(bundles, findings, [], [])

    triage.run_synthesis_arm(
        bundles, findings, summary, "lead-model",
        repeats=1, concurrency=1,
        models=["model-b", "model-c"],
        provider="lead-prov",
        providers=["prov-b", "prov-c"],
    )

    assert seen["lead-model"] == "lead-prov"    # the leader uses --synthesis-provider
    assert seen["model-b"] == "prov-b"          # positional pins
    assert seen["model-c"] == "prov-c"


def test_ensemble_without_providers_falls_back_to_the_single_provider(
    monkeypatch, bundles, findings
):
    """No --synthesis-providers is the pre-ensemble behaviour: every member on
    the single --synthesis-provider."""
    seen: dict[str, str] = {}

    class _Rec:
        def __init__(self, *, api_key=None, model="", provider="", **_kw):
            seen[model] = provider
            self.usage = LlmUsage()
            self.provider_pin = provider
            self.provider_preference = screening.build_provider(provider)

        def __enter__(self):
            return self

        def __exit__(self, *_exc):
            return None

        def complete(self, messages, **_kw):
            return {"correlated_findings": []}

    monkeypatch.setattr(screening, "OpenRouterCorrelator", _Rec)
    summary = join.summarise(bundles, findings, [], [])

    triage.run_synthesis_arm(
        bundles, findings, summary, "lead-model",
        repeats=1, concurrency=1,
        models=["model-b"],
        provider="shared-prov",
    )

    assert seen == {"lead-model": "shared-prov", "model-b": "shared-prov"}


def test_synthesis_records_its_decoding_parameters(
    monkeypatch, bundles, findings
):
    """temp/seed/_supported travel with pass 2 the way they do with pass 1 and
    verify — this was the one LLM pass that recorded its decoding params
    nowhere, even though it runs through the same send site at temperature 0.
    """
    client = _FakeClient()
    monkeypatch.setattr(screening, "OpenRouterCorrelator", lambda **_kw: client)

    summary = join.summarise(bundles, findings, [])
    _, metadata = triage.run_synthesis_arm(
        bundles, findings, summary, "stub-model", repeats=1)

    # temperature / seed are the shared constants, scalar — not model-specific.
    assert metadata["temperature"] == screening.TEMPERATURE
    assert metadata["seed"] == screening.SEED
    # capabilities and the honoured-flags are keyed by model, because this pass
    # (unlike triage's `llm` and verify's `loop`) can run an ensemble.
    assert metadata["model_capabilities"] == {"stub-model": client.capabilities}
    assert metadata["seed_supported"] == {"stub-model": True}
    assert metadata["temperature_supported"] == {"stub-model": True}


def test_synthesis_decoding_support_is_recorded_per_ensemble_member(
    monkeypatch, bundles, findings
):
    """An ensemble can mix a model whose provider honours the seed with one that
    silently drops it; a single scalar flag would hide that, so support is a map
    and a measured "no" stays distinct from an unknown (unreadable catalogue).
    """
    caps = {
        "lead-model": {"seed": True, "temperature": True},
        "model-b": {"seed": False, "temperature": True},
        "model-c": None,   # catalogue unreachable for this id — unknown, not "no"
    }

    class _Rec:
        def __init__(self, *, api_key=None, model="", provider="", **_kw):
            self.model = model
            self.usage = LlmUsage()
            self.provider_pin = provider
            self.provider_preference = screening.build_provider(provider)
            self.capabilities = caps[model]

        def __enter__(self):
            return self

        def __exit__(self, *_exc):
            return None

        def complete(self, messages, **_kw):
            return {"correlated_findings": []}

    monkeypatch.setattr(screening, "OpenRouterCorrelator", _Rec)
    summary = join.summarise(bundles, findings, [])

    _, metadata = triage.run_synthesis_arm(
        bundles, findings, summary, "lead-model",
        repeats=1, concurrency=1, models=["model-b", "model-c"])

    assert metadata["models"] == ["lead-model", "model-b", "model-c"]
    assert metadata["model_capabilities"] == caps
    assert metadata["seed_supported"] == {
        "lead-model": True, "model-b": False, "model-c": None}
    assert metadata["temperature_supported"] == {
        "lead-model": True, "model-b": True, "model-c": None}


def test_the_dry_run_dump_stores_the_shared_pass1_system_prompt_once(
    bundles, findings, tmp_path
):
    # Pass 1 is many small calls that share only the system prompt, so the
    # dump stores that header ONCE and each call keeps only the per-endpoint
    # user turn — not a copy of the header per endpoint (the redundancy the
    # dump used to carry). See triage.driver.dry_run.
    from dast_orchestrator.stages.triage import driver

    path = driver.dry_run(
        bundles, findings,
        out_dir=tmp_path, timestamp="20260101T000000Z",
    )
    dump = json.loads(path.read_text())
    pass1 = dump["pass1_screening"]
    assert pass1["system"] == screening.SYSTEM_PROMPT     # hoisted, once
    assert len(pass1["calls"]) > 1                          # several calls...
    # ...none of which repeats the system header
    for call in pass1["calls"]:
        assert [m["role"] for m in call["messages"]] == ["user"]
