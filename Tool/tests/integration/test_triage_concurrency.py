"""Pass 1 runs its calls concurrently — and must produce the same artifact.

The calls are independent by construction (one endpoint per call is the design
of the pass), so parallelising them is pure wall-clock. What these tests protect
is that "pure wall-clock" is actually true: the same verdicts, the same
accounting, and an artifact that still diffs cleanly against another run.

No network: the correlator's ``analyse`` is replaced with a stub that sleeps
briefly, so concurrency is observable without a model.
"""

from __future__ import annotations

import time

import pytest

from dast_orchestrator.analysis import join
from dast_orchestrator.analysis import screening
from dast_orchestrator.stages import triage
from dast_orchestrator.analysis.join import AlertGroup, Bundle
from dast_orchestrator.analysis.screening import LlmError, LlmUsage


def _bundle(index: int) -> Bundle:
    group = AlertGroup(
        plugin_id="40018", name="SQL Injection", risk="High", confidence="Medium",
        param="q", evidence="e", method="GET", urls=[f"http://t/{index}"],
    )
    return Bundle(
        endpoint_key=f"GET /e{index}", match_how="seed", method="GET",
        path=f"/e{index}", static_context={"key": f"GET /e{index}"}, groups=[group],
    )


@pytest.fixture
def scan():
    bundles = [_bundle(i) for i in range(12)]
    findings = join.build_findings(bundles)
    return bundles, findings


class _StubUsage:
    prompt_tokens = 100
    completion_tokens = 20
    cost = 0.001


class _StubResult:
    usage = _StubUsage()
    model = "m/x"
    id = "gen-1"
    choices: list = []


class _StubClient:
    """Stands in for OpenRouterCorrelator: no network, real accounting."""

    def __init__(self, *_a, delay: float = 0.02, fail_on: set[str] | None = None,
                 **_k) -> None:
        self.usage = LlmUsage()
        self.delay = delay
        self.fail_on = fail_on or set()
        self.in_flight = 0
        self.peak_in_flight = 0
        self.provider_pin = ""
        self.provider_preference = screening.build_provider("")

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        return None

    def analyse(self, bundle, chunk, max_tokens=0, cross_endpoint=None,
                system_prompt=None, assembler=None, retrieval=None,
                retrieval_tools=None, max_retrievals=0, oracle=None):
        self.in_flight += 1
        self.peak_in_flight = max(self.peak_in_flight, self.in_flight)
        try:
            time.sleep(self.delay)
            if bundle.identifier in self.fail_on:
                raise LlmError("nope", "not_json")
            # Stand in for the network, not for the accounting: the real client
            # records tokens and one call-log entry per HTTP call, and that is
            # exactly the shared state under test.
            self.usage.record_tokens(_StubUsage())
            self.usage.record_call(
                pass_name="triage", label=bundle.identifier, model_requested="m/x",
                latency_ms=1.0, result=_StubResult(), outcome="ok",
            )
            return {
                "alert_verdicts": [
                    {"finding_id": fid, "needs_rescan": True, "confidence": 70,
                     "reasoning": "r", "suggested_tool": "sqlmap"}
                    for fid, _ in chunk
                ]
            }
        finally:
            self.in_flight -= 1


def _run(monkeypatch, scan, concurrency, **client_kwargs):
    bundles, findings = scan
    client = _StubClient(**client_kwargs)
    monkeypatch.setattr(screening, "OpenRouterCorrelator",
                        lambda *a, **k: client)
    monkeypatch.setattr(screening, "model_capabilities", lambda *a, **k: None)
    meta = triage.run_llm_arm(bundles, findings, "m/x", 0,
                              api_key="k", concurrency=concurrency)
    return meta, findings, client


def test_concurrent_and_sequential_produce_the_same_verdicts(monkeypatch, scan):
    bundles, _ = scan
    seq_meta, seq_findings, _ = _run(monkeypatch, (bundles, join.build_findings(bundles)), 1)
    par_meta, par_findings, _ = _run(monkeypatch, (bundles, join.build_findings(bundles)), 6)

    assert [f["llm"] for f in seq_findings] == [f["llm"] for f in par_findings]
    assert [f["llm_asked"] for f in seq_findings] == [f["llm_asked"] for f in par_findings]
    for key in ("calls", "prompt_tokens", "failed_calls", "failure_kinds"):
        assert seq_meta["usage"][key] == par_meta["usage"][key], key
    assert seq_meta["dropped_unknown_finding_ids"] == par_meta["dropped_unknown_finding_ids"]


class _SourceForOne:
    """Just enough of an Assembler: source for one endpoint, none for the rest."""

    code_enabled = False
    code_level = "none"

    def __init__(self, identifier):
        self.identifier = identifier

    def prepare(self, _bundles):
        pass

    def as_dict(self):
        return {"excerpt_policy": {"name": "none"}, "http_exchanges_available": 0}

    def has_source(self, bundle):
        return bundle.identifier == self.identifier


def test_an_endpoint_with_no_context_is_asked_and_its_verdict_says_so(monkeypatch, scan):
    bundles, findings = scan
    bundles[1].static_context = None
    monkeypatch.setattr(screening, "OpenRouterCorrelator", lambda *a, **k: _StubClient())
    monkeypatch.setattr(screening, "model_capabilities", lambda *a, **k: None)

    triage.run_llm_arm(bundles, findings, "m/x", 0, api_key="k",
                       assembler=_SourceForOne(bundles[0].identifier))

    by_endpoint = {f["endpoint_key"]: f for f in findings}
    no_context = by_endpoint[bundles[1].endpoint_key]
    assert no_context["llm_asked"] is True
    assert no_context["llm"]["had_source"] is False
    assert by_endpoint[bundles[0].endpoint_key]["llm"]["had_source"] is True


def test_calls_actually_overlap(monkeypatch, scan):
    _, _, client = _run(monkeypatch, scan, 6)
    assert client.peak_in_flight > 1, "the pool did not run anything in parallel"


def test_concurrency_one_is_strictly_sequential(monkeypatch, scan):
    _, _, client = _run(monkeypatch, scan, 1)
    assert client.peak_in_flight == 1


def test_no_counter_is_lost_under_concurrency(monkeypatch, scan):
    # Every counter is a read-modify-write; unsynchronised `+=` from several
    # workers silently drops increments, and a cost total that is quietly short
    # is worse than no number at all.
    meta, findings, _ = _run(monkeypatch, scan, 8)
    usage = meta["usage"]
    assert usage["calls"] == len(findings) == 12
    assert len(usage["calls_log"]) == 12
    assert usage["prompt_tokens"] == 12 * 100
    assert usage["cost_usd"] == pytest.approx(12 * 0.001)


def test_usage_counters_survive_a_thread_storm():
    # The lock, exercised directly and hard: 16 threads x 200 increments each.
    # Unsynchronised this loses counts on CPython reliably.
    from concurrent.futures import ThreadPoolExecutor

    usage = LlmUsage()

    def hammer():
        for _ in range(200):
            usage.record_tokens(_StubUsage())
            usage.record_call(pass_name="p", label="l", model_requested="m",
                              latency_ms=1.0, result=_StubResult(), outcome="ok")
            usage.record_failure("not_json")
            usage.note_retry()
            usage.note_split()

    with ThreadPoolExecutor(max_workers=16) as pool:
        for future in [pool.submit(hammer) for _ in range(16)]:
            future.result()

    total = 16 * 200
    assert usage.calls == total
    assert usage.prompt_tokens == total * 100
    assert usage.failures == total and usage.failure_kinds == {"not_json": total}
    assert usage.retries == total and usage.splits == total
    assert len(usage.calls_log) == total


def test_a_failing_endpoint_stays_asked_and_does_not_take_the_run_down(monkeypatch, scan):
    meta, findings, _ = _run(monkeypatch, scan, 6, fail_on={"GET /e3"})
    assert meta["usage"]["failed_calls"] == 1
    assert meta["usage"]["failure_kinds"] == {"not_json": 1}
    failed = [f for f in findings if f["endpoint_key"] == "GET /e3"]
    # asked-but-unanswered must stay distinguishable from never-asked
    assert all(f["llm_asked"] for f in failed)
    assert all(f.get("llm") is None for f in failed)
    assert sum(1 for f in findings if f.get("llm")) == 11


def test_call_log_order_is_stable_not_chronological(monkeypatch, scan):
    # With a pool, completion order varies run to run; a chronological log would
    # make two runs of the same scan undiffable for no reason.
    bundles, _ = scan
    first, _, _ = _run(monkeypatch, (bundles, join.build_findings(bundles)), 6)
    second, _, _ = _run(monkeypatch, (bundles, join.build_findings(bundles)), 6)
    labels = lambda m: [c["label"] for c in m["usage"]["calls_log"]]
    assert labels(first) == labels(second) == sorted(labels(first))


def test_metadata_records_the_concurrency_it_ran_at(monkeypatch, scan):
    # Without it the per-call latencies and the stage's wall time look
    # contradictory.
    meta, _, _ = _run(monkeypatch, scan, 6)
    assert meta["concurrency"] == 6


def test_pass_one_hands_the_client_both_ceilings_unaltered(monkeypatch, scan):
    # Only the client's budget combines the two ceilings with the run's earlier
    # spend; a caller that pre-subtracted it would count it twice again.
    bundles, findings = scan
    seen: dict = {}

    def _client(*_a, **kwargs):
        seen.update(kwargs)
        return _StubClient()

    monkeypatch.setattr(screening, "OpenRouterCorrelator", _client)
    monkeypatch.setattr(screening, "model_capabilities", lambda *a, **k: None)
    triage.run_llm_arm(bundles, findings, "m/x", 0, api_key="k",
                       stage_max_cost_usd=-1.0, run_max_cost_usd=2.0,
                       prior_cost_usd=1.27)

    assert (seen["stage_max_cost_usd"], seen["run_max_cost_usd"],
            seen["prior_cost_usd"]) == (-1.0, 2.0, 1.27)


def test_findings_the_limit_defers_are_recorded_and_never_sent(monkeypatch, scan):
    bundles, findings = scan
    for bundle in bundles[6:]:
        bundle.static_context = None             # beyond the old gate
    client = _StubClient()
    monkeypatch.setattr(screening, "OpenRouterCorrelator", lambda *a, **k: client)
    monkeypatch.setattr(screening, "model_capabilities", lambda *a, **k: None)

    meta = triage.run_llm_arm(bundles, findings, "m/x", 0, api_key="k",
                              max_unmatched_findings=2)

    gated = {b.identifier for b in bundles[:6]}
    sent = {entry["label"] for entry in client.usage.calls_log}
    assert gated <= sent and len(sent - gated) == 2
    deferred = [f for f in findings if f["llm_deferred"]]
    assert len(deferred) == 4
    assert not any(f["llm_asked"] for f in deferred)
    assert meta["scope"]["deferred"] == 4
    assert sum(meta["scope"]["deferred_by_risk"].values()) == 4
    assert join.summarise(bundles, findings, [])["llm_findings_deferred"] == 4
