"""Unit tests for the LLM arm, using a recorded response — never the network.

`uv run pytest` must stay free and offline, so the OpenRouter client is driven
with a fixture that has the same shape a real completion has. What is tested is
everything around the model: prompt construction, the structured-output
contract, and the merge back into the findings — including the case where the
model returns an id it was never given.
"""

from __future__ import annotations

import json
from pathlib import Path

#: Shared fixture corpus, one level up now that tests are grouped by kind.
FIXTURES_DIR = Path(__file__).resolve().parents[1] / "fixtures"

import jsonschema
import pytest

from dast_orchestrator.analysis import join
from dast_orchestrator.analysis import screening
from dast_orchestrator.analysis.join import RunArtifacts
from dast_orchestrator.analysis.screening import LlmError, OpenRouterCorrelator
from dast_orchestrator.adapters.noir_runner import (
    build_ai_context_artifact,
    build_seed_map_artifact,
    parse_endpoints,
)

FIXTURES = FIXTURES_DIR
TARGET = "http://target-gitea:3000"


@pytest.fixture
def run() -> RunArtifacts:
    endpoints = parse_endpoints(
        json.loads((FIXTURES / "noir-gitea-sample.json").read_text())
    )
    return RunArtifacts(
        timestamp="20260817T114501Z",
        ai_context=build_ai_context_artifact(endpoints, Path("/src"), "20260817T114501Z"),
        zap_report=json.loads((FIXTURES / "zap-alerts-sample.json").read_text()),
        seed_map=build_seed_map_artifact(endpoints, TARGET, "20260817T114501Z"),
        ai_context_path=Path("noir-ai-context-20260817T114501Z.json"),
        zap_report_path=Path("zap-alerts-20260817T114501Z.json"),
        seed_map_path=Path("noir-seed-map-20260817T114501Z.json"),
    )


@pytest.fixture
def login_bundle(run):
    bundles = {b.identifier: b for b in join.build_bundles(run)}
    return bundles["POST /user/login"]


@pytest.fixture
def findings(run):
    return join.build_findings(join.build_bundles(run))


@pytest.fixture
def pairs(login_bundle, findings):
    ids = {f["finding_id"] for f in findings}
    return [
        (join.finding_id(login_bundle, g), g)
        for g in login_bundle.groups
        if join.finding_id(login_bundle, g) in ids
    ]


@pytest.fixture
def recorded_response(pairs):
    """The recorded completion, with its placeholder ids bound to this run.

    finding_ids are content hashes, so hard-coding them in the fixture would
    make it rot the moment the sample alerts change. Binding them here keeps
    the fixture about the *shape* of a response, which is what it is for.
    """
    text = (FIXTURES / "openrouter-response.json").read_text()
    by_confidence = {group.confidence: fid for fid, group in pairs}
    text = text.replace("__SQLI_MEDIUM__", by_confidence["Medium"])
    text = text.replace("__SQLI_HIGH__", by_confidence["High"])
    return json.loads(text)


def parsed(recorded_response) -> dict:
    return json.loads(recorded_response["choices"][0]["message"]["content"])


# -- prompt construction ---------------------------------------------------


def test_payload_carries_the_static_context_the_prompt_relies_on(login_bundle, pairs):
    payload = screening.build_user_payload(login_bundle, pairs)
    assert payload["endpoint"]["route"] == "POST /user/login"
    assert payload["endpoint"]["static_context_available"] is True
    assert payload["static_context"]["guards"]
    assert payload["static_context"]["guards"][0]["confidence"] is not None
    assert len(payload["alerts"]) == 2


def test_empty_noir_categories_are_named_rather_than_omitted(login_bundle, pairs):
    # Noir populates `validators` on 2 of 354 Gitea endpoints. If an empty
    # category simply vanished from the payload, the model could not tell
    # "analyser found nothing" from "field not sent", and the prompt's rule 2
    # would be unenforceable.
    payload = screening.build_user_payload(login_bundle, pairs)
    assert "validators" in payload["static_context_categories_not_found"]
    assert "validators" not in payload["static_context"]


def test_snippets_are_trimmed_so_prompt_size_stays_bounded(login_bundle, pairs):
    payload = screening.build_user_payload(login_bundle, pairs)
    for signals in payload["static_context"].values():
        for signal in signals:
            assert len(signal["snippet"]) <= screening.MAX_SNIPPET_CHARS


def test_messages_are_system_plus_one_user_json_message(login_bundle, pairs):
    messages = screening.build_messages(login_bundle, pairs)
    assert [m["role"] for m in messages] == ["system", "user"]
    assert messages[0]["content"] == screening.SYSTEM_PROMPT
    json.loads(messages[1]["content"])


def test_pass_one_no_longer_asks_for_cross_endpoint_findings():
    # Pass 1 sees one endpoint (since chunking, six alerts of one endpoint) per
    # call, so it cannot correlate across endpoints — asking it to was what
    # produced two runs of zero correlated findings. Synthesis is pass 2's job
    # and its schema, and pass 1's schema must not offer the field at all.
    assert screening.RESPONSE_SCHEMA["required"] == ["alert_verdicts"]
    assert "correlated_findings" not in screening.RESPONSE_SCHEMA["properties"]


def test_pinned_parameters_are_not_floating_aliases():
    assert screening.TEMPERATURE == 0.0
    for floating in (":online", ":free", "latest"):
        assert floating not in screening.MODEL


# -- the structured-output contract ----------------------------------------


def test_recorded_response_satisfies_the_declared_schema(recorded_response):
    jsonschema.validate(parsed(recorded_response), screening.RESPONSE_SCHEMA)


def test_response_schema_is_itself_valid():
    jsonschema.Draft202012Validator.check_schema(screening.RESPONSE_SCHEMA)


# -- parsing and merging ---------------------------------------------------


class _FakeChat:
    def __init__(self, payload: dict) -> None:
        self._payload = payload
        self.last_kwargs: dict = {}

    def send(self, **kwargs):
        self.last_kwargs = kwargs
        return _obj(self._payload)


def _obj(data):
    """Turn the recorded JSON into attribute access, as the SDK returns."""
    if isinstance(data, dict):
        return type("Node", (), {k: _obj(v) for k, v in data.items()})()
    if isinstance(data, list):
        return [_obj(item) for item in data]
    return data


def _correlator(payload: dict) -> OpenRouterCorrelator:
    client = OpenRouterCorrelator.__new__(OpenRouterCorrelator)
    client.model = screening.MODEL
    client.temperature = screening.TEMPERATURE
    client.usage = screening.LlmUsage()
    client.provider_pin = ""
    client.provider_preference = screening.build_provider("")
    client._client = type("SDK", (), {"chat": _FakeChat(payload)})()
    return client


def test_analyse_parses_content_and_records_usage(login_bundle, pairs, recorded_response):
    client = _correlator(recorded_response)
    response = client.analyse(login_bundle, pairs)
    assert len(response["alert_verdicts"]) == 2
    assert client.usage.calls == 1
    assert client.usage.prompt_tokens == 1873
    # Cost is reported, not estimated: "can CI afford this" needs a real number.
    assert client.usage.cost_usd == pytest.approx(0.006656)


def test_analyse_sends_the_pinned_parameters(login_bundle, pairs, recorded_response):
    client = _correlator(recorded_response)
    client.analyse(login_bundle, pairs)
    sent = client._client.chat.last_kwargs
    assert sent["model"] == screening.MODEL
    assert sent["temperature"] == screening.TEMPERATURE
    assert sent["stream"] is False
    assert sent["response_format"].json_schema.strict is True


def test_non_json_content_is_an_error_not_a_silent_empty_result(login_bundle, pairs):
    broken = {"choices": [{"message": {"content": "I cannot help with that."}}]}
    with pytest.raises(LlmError):
        _correlator(broken).analyse(login_bundle, pairs)


def test_a_synthesis_deadline_is_a_non_transient_timeout_not_a_retry():
    # Only the synthesis call sets a deadline. When it fires, the provider
    # accepted the request and then stalled: classify it as a non-transient
    # `timeout` so the caller degrades at once. The trap it avoids is that
    # "timeout" is a TRANSIENT_MARKER — without this branch the hang would be
    # retried, waiting out the same stall two more times.
    import httpx

    class _HangingChat:
        def __init__(self) -> None:
            self.calls = 0
            self.last_kwargs: dict = {}

        def send(self, **kwargs):
            self.calls += 1
            self.last_kwargs = kwargs
            raise httpx.ReadTimeout("read timed out")

    client = OpenRouterCorrelator.__new__(OpenRouterCorrelator)
    client.model = screening.MODEL
    client.temperature = screening.TEMPERATURE
    client.usage = screening.LlmUsage()
    client.provider_pin = ""
    client.provider_preference = screening.build_provider("")
    chat = _HangingChat()
    client._client = type("SDK", (), {"chat": chat})()

    with pytest.raises(LlmError) as exc:
        client.complete(
            [{"role": "user", "content": "x"}],
            schema_name="s", schema={"type": "object"},
            schema_description="d", timeout=5,
        )
    assert exc.value.kind == "timeout"
    assert chat.last_kwargs["timeout_ms"] == 5000   # a real deadline was set
    assert chat.calls == 1                           # the hang was not retried


# -- the failure modes observed in the first live run ----------------------
#
# All four of these cost a whole endpoint in the first Phase 3 run against
# deepseek-v4-flash. They are pinned here so a future prompt or model change
# cannot quietly reintroduce them.


def test_fenced_json_is_unwrapped_rather_than_discarded(login_bundle, pairs, recorded_response):
    # One endpoint came back wrapped in a ```json fence despite strict mode.
    # The answer was well-formed; throwing it away over three backticks isn't.
    inner = recorded_response["choices"][0]["message"]["content"]
    fenced = {"choices": [{"message": {"content": f"```json\n{inner}\n```"}}]}
    response = _correlator(fenced).analyse(login_bundle, pairs)
    assert len(response["alert_verdicts"]) == 2


def test_truncated_response_is_named_as_truncation(login_bundle, pairs):
    # finish_reason=length is what killed the 45-alert endpoint. A generic
    # "not JSON" message sent the diagnosis down the wrong path for a while.
    truncated = {
        "choices": [
            {"finish_reason": "length", "message": {"content": '{"alert_verdicts": [{"finding'}}
        ]
    }
    client = _correlator(truncated)
    with pytest.raises(LlmError, match="truncated") as exc:
        client.analyse(login_bundle, pairs)
    assert exc.value.kind == "truncated"
    # Retrying a truncation would truncate again at the same ceiling.
    assert client.usage.retries == 0


def test_empty_content_with_reasoning_is_distinguished_from_plain_empty(login_bundle, pairs):
    # This model spends completion budget on reasoning; four endpoints returned
    # reasoning and no answer. That is a different problem from an empty reply
    # and the artifact should be able to say which happened.
    reasoning_only = {
        "choices": [{"message": {"content": "", "reasoning": "Considering the guards..."}}]
    }
    with pytest.raises(LlmError) as exc:
        _correlator(reasoning_only).analyse(login_bundle, pairs)
    assert exc.value.kind == "empty_reasoning_only"
    assert "reasoning present" in str(exc.value)


def test_a_non_deterministic_failure_is_retried_once(login_bundle, pairs, recorded_response):
    # The observed empty-message failures were not reproducible, so one retry
    # recovers the endpoint for a fraction of a cent.
    client = _correlator(recorded_response)
    attempts = {"n": 0}
    good = client._client.chat.send

    def flaky(**kwargs):
        attempts["n"] += 1
        if attempts["n"] == 1:
            return _obj({"choices": [{"message": {"content": ""}}]})
        return good(**kwargs)

    client._client.chat.send = flaky
    response = client.analyse(login_bundle, pairs)
    assert len(response["alert_verdicts"]) == 2
    assert client.usage.retries == 1


def test_failure_kinds_are_counted_so_a_lossy_run_says_how(login_bundle, pairs):
    usage = screening.LlmUsage()
    usage.record_failure("truncated")
    usage.record_failure("empty_reasoning_only")
    usage.record_failure("empty_reasoning_only")
    assert usage.failures == 3
    assert usage.as_dict()["failure_kinds"] == {"empty_reasoning_only": 2, "truncated": 1}


# -- chunking --------------------------------------------------------------


def test_oversized_bundles_are_split_not_truncated():
    items = [(f"f-{i:012d}", None) for i in range(45)]
    chunks = screening.chunk_alerts(items, size=12)
    assert [len(c) for c in chunks] == [12, 12, 12, 9]
    # Nothing may be dropped: the 45-alert endpoint lost all 45 verdicts to a
    # truncated response before chunking existed.
    assert sum(len(c) for c in chunks) == 45


def test_small_bundles_stay_a_single_call():
    items = [(f"f-{i:012d}", None) for i in range(4)]
    assert len(screening.chunk_alerts(items, size=12)) == 1


def test_merge_writes_verdicts_and_labels_the_arm_delta(findings, pairs, recorded_response):
    applied, unknown = screening.merge_verdicts(
        findings, parsed(recorded_response), [fid for fid, _ in pairs]
    )
    assert (applied, unknown) == (2, [])

    by_id = {f["finding_id"]: f for f in findings}
    medium = by_id[next(fid for fid, g in pairs if g.confidence == "Medium")]
    high = by_id[next(fid for fid, g in pairs if g.confidence == "High")]

    # Both arms want the Medium-confidence SQLi verified -> "both".
    assert medium["llm"]["needs_rescan"] is True
    assert medium["agreement"] == "both"
    # The table rescans 40018 unconditionally; the model declines at High
    # confidence. That disagreement IS the measured delta of Phase 3.
    assert high["deterministic"]["needs_rescan"] is True
    assert high["llm"]["needs_rescan"] is False
    assert high["agreement"] == "deterministic-only"


def test_merge_records_whether_the_model_had_source(findings, pairs, recorded_response):
    ids = [fid for fid, _ in pairs]
    screening.merge_verdicts(findings, parsed(recorded_response), ids)
    assert {f["llm"]["had_source"] for f in findings if f.get("llm")} == {False}
    screening.merge_verdicts(findings, parsed(recorded_response), ids, had_source=True)
    assert {f["llm"]["had_source"] for f in findings if f.get("llm")} == {True}


def test_verdicts_for_ids_that_were_never_sent_are_dropped(findings, pairs, recorded_response):
    response = parsed(recorded_response)
    response["alert_verdicts"].append(
        {"finding_id": "f-deadbeefdead", "needs_rescan": True, "verdict": "x",
         "confidence": "high", "reasoning": "", "suggested_tool": "none"}
    )
    applied, unknown = screening.merge_verdicts(
        findings, response, [fid for fid, _ in pairs]
    )
    assert applied == 2
    assert unknown == ["f-deadbeefdead"]


def test_metadata_records_everything_needed_to_rerun_the_pass():
    usage = screening.LlmUsage(calls=52, prompt_tokens=100, completion_tokens=10)
    metadata = screening.run_metadata(screening.MODEL, usage, 52)
    assert metadata["system_prompt"] == screening.SYSTEM_PROMPT
    assert metadata["response_schema"] == screening.RESPONSE_SCHEMA
    assert metadata["model"] == screening.MODEL
    assert metadata["usage"]["calls"] == 52


def test_missing_api_key_fails_with_an_actionable_message(monkeypatch):
    monkeypatch.delenv("SHARED_OPENROUTER_API_KEY", raising=False)
    with pytest.raises(LlmError, match="SHARED_OPENROUTER_API_KEY"):
        screening.api_key_from_env()


def test_empty_verdict_list_is_a_failure_not_a_silent_loss(login_bundle, pairs):
    # Observed on three endpoints in the second live run: valid JSON, schema
    # satisfied, zero verdicts — every alert in the chunk silently unanswered
    # with nothing logged. Every call carries at least one alert, so an empty
    # list is always a failure to follow the instruction.
    empty = {
        "choices": [
            {
                "finish_reason": "stop",
                "message": {
                    "content": '{"alert_verdicts": [], "correlated_findings": []}'
                },
            }
        ]
    }
    with pytest.raises(LlmError) as exc:
        _correlator(empty).analyse(login_bundle, pairs)
    assert exc.value.kind == "no_verdicts"


def test_chunk_size_leaves_headroom_under_the_token_ceiling():
    # A 10-alert chunk still truncated at 8192 tokens, because this model's
    # reasoning is billed from the completion budget.
    assert screening.MAX_ALERTS_PER_CALL <= 6
    assert screening.MAX_TOKENS >= 8192


# -- per-call telemetry ----------------------------------------------------


def test_every_call_is_logged_with_routing_and_latency(login_bundle, pairs, recorded_response):
    client = _correlator(recorded_response)
    client.analyse(login_bundle, pairs)
    entry = client.usage.calls_log[0]
    assert entry["pass"] == "screening"
    assert entry["label"] == "POST /user/login"
    assert entry["model_requested"] == screening.MODEL
    assert entry["outcome"] == "ok"
    assert entry["latency_ms"] >= 0
    assert entry["prompt_tokens"] == 1873
    # The key to look this call up in OpenRouter's dashboard months later.
    assert entry["generation_id"] == "gen-fixture-0001"


def test_a_failed_call_is_logged_with_its_cause(login_bundle, pairs):
    broken = {"choices": [{"message": {"content": "not json"}}]}
    client = _correlator(broken)
    with pytest.raises(LlmError):
        client.analyse(login_bundle, pairs)
    # Both the initial attempt and the retry are logged: a run that spent money
    # on failures must show that in its cost record.
    assert [c["outcome"] for c in client.usage.calls_log] == ["not_json", "not_json"]


def test_usage_summarises_latency_and_providers(login_bundle, pairs, recorded_response):
    client = _correlator(recorded_response)
    client.analyse(login_bundle, pairs)
    usage = client.usage.as_dict()
    assert set(usage["latency_ms"]) == {"min", "median", "max", "total"}
    assert usage["providers"]


def test_a_provider_policy_refusal_becomes_actionable_advice(login_bundle, pairs):
    # OpenRouter answers 404 "No endpoints available matching your guardrail
    # restrictions and data policy" when the account's privacy settings exclude
    # every provider serving the model. That is a settings problem, not a
    # missing model, and it used to surface as a raw traceback.
    class _Refusing:
        def send(self, **_kwargs):
            raise RuntimeError(
                "No endpoints available matching your guardrail restrictions "
                "and data policy. Configure: https://openrouter.ai/settings/privacy"
            )

    client = _correlator({})
    client._client = type("SDK", (), {"chat": _Refusing()})()
    with pytest.raises(LlmError) as exc:
        client.analyse(login_bundle, pairs)
    assert exc.value.kind == "no_provider"
    assert "settings/privacy" in str(exc.value)
    assert "several providers" in str(exc.value)


def test_a_single_alert_gets_more_room_rather_than_being_lost():
    # qwen3-235b truncated on chunks of ONE alert, which cannot be split
    # further. Without a bigger ceiling those findings are simply lost, which
    # is what happened on the live comparison run.
    assert screening.RETRY_MAX_TOKENS > screening.MAX_TOKENS


def test_routing_metadata_is_requested_on_every_call(login_bundle, pairs, recorded_response):
    # OpenRouter only returns the routing block when asked. Without this the
    # provider, strategy and region fields log as null — which is exactly what
    # both live comparison runs recorded.
    client = _correlator(recorded_response)
    client.analyse(login_bundle, pairs)
    assert client._client.chat.last_kwargs["x_open_router_metadata"] == "enabled"


def test_provider_and_generation_id_are_captured_when_present():
    # The metadata shape here is the REAL one, checked against a live call on
    # 2026-08-28. It previously used an invented `attempts` list; the test
    # passed and thereby certified a provider capture that had never once worked
    # against the API, because the fixture asserted the assumption rather than
    # the contract. Every recorded call in the project logged `provider: null`.
    usage = screening.LlmUsage()
    result = _obj(
        {
            "id": "gen-abc123",
            "model": "qwen/qwen3-235b-a22b-2507",
            "openrouter_metadata": {
                "strategy": "direct",
                "region": "eu",
                "attempt": 1,
                "attempts": None,
                "endpoints": {"available": [
                    {"model": "qwen/qwen3-235b-a22b-2507",
                     "provider": "Together", "selected": False},
                    {"model": "qwen/qwen3-235b-a22b-2507",
                     "provider": "DeepInfra", "selected": True},
                ]},
            },
            "choices": [{"finish_reason": "stop", "message": {"content": "{}"}}],
            "usage": {"prompt_tokens": 10, "completion_tokens": 5, "cost": 0.001},
        }
    )
    usage.record_call(
        pass_name="screening", label="GET /x",
        model_requested="qwen/qwen3-235b-a22b-2507",
        latency_ms=1234.5, result=result, outcome="ok",
    )
    call = usage.calls_log[0]
    assert call["provider"] == "DeepInfra"
    assert call["vendor"] == "qwen"  # the model vendor, explicit, not just the id prefix
    assert call["generation_id"] == "gen-abc123"
    assert call["routing_strategy"] == "direct"
    assert usage.providers_used() == {"DeepInfra": 1}
    assert usage.latency_summary()["max"] == 1234.5


# -- model capabilities travel with the run --------------------------------


def test_capabilities_distinguish_unknown_from_unsupported(monkeypatch):
    # `seed: 20260817` in an artifact must never be read as "this run was
    # deterministic" when the model never accepted a seed. A catalogue that could
    # not be read is None, not False — a missing measurement and a measured "no"
    # must stay distinguishable.
    class _Response:
        @staticmethod
        def raise_for_status():
            return None

        @staticmethod
        def json():
            return {"data": [{"id": "m/free", "supported_parameters":
                              ["response_format", "temperature"],
                              "context_length": 1000}]}

    import httpx

    monkeypatch.setattr(httpx, "get", lambda *a, **k: _Response())
    caps = screening.model_capabilities("m/free")
    assert caps["seed"] is False and caps["structured_outputs"] is False
    assert caps["response_format"] is True
    assert screening.model_capabilities("m/absent") is None

    def boom(*a, **k):
        raise RuntimeError("offline")

    monkeypatch.setattr(httpx, "get", boom)
    assert screening.model_capabilities("m/free") is None


def test_run_metadata_records_whether_the_seed_could_be_honoured(monkeypatch):
    monkeypatch.setattr(screening, "model_capabilities",
                        lambda *a, **k: {"seed": False, "structured_outputs": False,
                                         "response_format": True,
                                         "context_length": 1, "pricing": {}})
    meta = screening.run_metadata("m/free", screening.LlmUsage(), 3)
    assert meta["seed"] == screening.SEED       # what was requested
    assert meta["seed_supported"] is False          # what the model can do
    assert meta["model_capabilities"]["structured_outputs"] is False


# -- transient failures vs bad answers -------------------------------------
#
# Parallelising pass 1 makes rate limiting a predictable failure rather than a
# rare one: six workers can trip a per-minute ceiling the sequential pass never
# approached. A 429 that kills an endpoint costs a verdict for a reason that has
# nothing to do with the model's judgment, so the two failure kinds get separate
# budgets.


@pytest.mark.parametrize(
    "message, transient",
    [("429 Too Many Requests", True),
     ("Rate limit exceeded", True),
     ("upstream 503", True),
     ("read timed out", True),
     ("Provider returned error", True),
     ("400 Bad Request: schema invalid", False),
     ("model not found", False)],
)
def test_transient_classification(message, transient):
    assert screening.OpenRouterCorrelator._is_transient(Exception(message)) is transient


@pytest.mark.parametrize(
    "message, overflow",
    [("This model's maximum context length is 65536 tokens", True),
     ("400 context_length_exceeded", True),
     ("Please reduce the length of the messages", True),
     ("prompt is too long: 210000 tokens", True),
     ("429 Too Many Requests", False),
     ("400 Bad Request: schema invalid", False)],
)
def test_context_overflow_classification(message, overflow):
    assert screening.OpenRouterCorrelator._is_context_overflow(
        Exception(message)) is overflow


def test_a_prompt_over_the_context_window_is_named_and_not_retried(login_bundle, pairs):
    # A whole-corpus synthesis on a large target can exceed the model's input
    # window; the provider rejects it with a 400 before generating anything.
    # That must surface as a classifiable `context_overflow`, not a raw
    # traceback that takes the run down, and it is never worth retrying unchanged.
    class _TooLong:
        def send(self, **_kwargs):
            raise RuntimeError(
                "400 This model's maximum context length is 65536 tokens, "
                "however you requested 210000 tokens"
            )

    client = _correlator({})
    client._client = type("SDK", (), {"chat": _TooLong()})()
    with pytest.raises(LlmError, match="context window") as exc:
        client.analyse(login_bundle, pairs)
    assert exc.value.kind == "context_overflow"
    assert client.usage.retries == 0


# -- a provider error that arrives on `.body`, not in str(exc) --------------
#
# OpenRouter can answer with a 200 whose body is `{"error": {...}}` and no
# `choices`; the SDK then raises a `ResponseValidationError` whose str() is a
# generic "Response validation failed…", and the provider's real message — an
# overflow notice, a rate limit, a fault — survives ONLY on `.body`. Read
# nowhere, every marker classifier matched the wrapper's prose, missed, and the
# error escaped `except LlmError` to take the Cacti synthesis stage down. These
# pin that the body is read and the synthesis call degrades rather than crashes.


class _WrappedBodyError(RuntimeError):
    """A faithful stand-in for ``openrouter.errors.ResponseValidationError``:
    a generic ``str()``, the provider's real message only on ``.body``."""

    def __init__(self, body: str) -> None:
        super().__init__("Response validation failed for Chat: None")
        self.body = body


_OVERFLOW_BODY = (
    '{"error":{"code":"invalid_request","message":"This endpoint\'s maximum '
    'context length is 131072 tokens. However, you requested about 133818 '
    'tokens."}}'
)
_UNCLASSIFIED_BODY = (
    '{"error":{"code":"invalid_request","message":"unsupported response_format"}}'
)
_TRANSIENT_BODY = '{"error":{"code":429,"message":"rate limit exceeded, retry later"}}'


def _raising_client(exc_factory):
    client = _correlator({})

    class _Chat:
        def __init__(self) -> None:
            self.calls = 0

        def send(self, **_kwargs):
            self.calls += 1
            raise exc_factory()

    chat = _Chat()
    client._client = type("SDK", (), {"chat": chat})()
    return client, chat


def test_provider_error_detail_reads_the_body_the_wrapper_hides():
    exc = _WrappedBodyError(_OVERFLOW_BODY)
    assert "maximum context length" not in str(exc).lower()   # not in the wrapper
    detail = screening.OpenRouterCorrelator._provider_error_detail(exc)
    assert "maximum context length" in detail.lower()         # recovered from .body
    assert "131072" in detail
    # Nothing to read on an ordinary exception — and no crash trying.
    assert screening.OpenRouterCorrelator._provider_error_detail(Exception("x")) == ""


def test_marker_classifiers_read_the_provider_body_not_just_the_wrapper():
    Corr = screening.OpenRouterCorrelator
    assert Corr._is_context_overflow(_WrappedBodyError(_OVERFLOW_BODY)) is True
    assert Corr._is_transient(_WrappedBodyError(_TRANSIENT_BODY)) is True
    # A body with no marker stays unclassified by both.
    assert Corr._is_context_overflow(_WrappedBodyError(_UNCLASSIFIED_BODY)) is False
    assert Corr._is_transient(_WrappedBodyError(_UNCLASSIFIED_BODY)) is False
    # An ordinary exception with no body is on the bit-identical old path.
    assert Corr._is_context_overflow(Exception("maximum context length")) is True
    assert Corr._is_transient(Exception("429")) is True


def test_an_overflow_in_the_error_body_is_classified_not_crashed():
    # The Cacti crash reproduced: str(exc) is the generic wrapper, the overflow
    # notice is only on .body. Read from the body it is a classifiable
    # `context_overflow` — the arm narrows a corpus — never a raw escape.
    client, chat = _raising_client(lambda: _WrappedBodyError(_OVERFLOW_BODY))
    with pytest.raises(LlmError) as exc:
        client.complete([{"role": "user", "content": "x"}],
                        schema_name="s", schema={"type": "object"},
                        schema_description="d", timeout=5400)
    assert exc.value.kind == "context_overflow"
    assert chat.calls == 1               # never retried unchanged
    assert client.usage.retries == 0


def test_an_unclassifiable_error_body_degrades_the_synthesis_call():
    # Neither overflow nor transient, but still must not crash the one
    # whole-corpus call: as a `provider_error` LlmError the arm degrades to "no
    # synthesis this run" and the chain continues to verify. The provider's own
    # words are carried into the message so the run records what actually failed.
    client, chat = _raising_client(lambda: _WrappedBodyError(_UNCLASSIFIED_BODY))
    with pytest.raises(LlmError) as exc:
        client.complete([{"role": "user", "content": "x"}],
                        schema_name="s", schema={"type": "object"},
                        schema_description="d", timeout=5400)
    assert exc.value.kind == "provider_error"
    assert "unsupported response_format" in str(exc.value)
    assert chat.calls == 1


def test_an_unclassifiable_error_without_a_deadline_still_raises_raw():
    # The degrade-not-crash backstop is gated on a deadline, which ONLY the
    # synthesis call sets. Pass 1 and verify (no timeout) keep raising a hard
    # provider error, so a real failure there is surfaced, not swallowed.
    client, chat = _raising_client(lambda: _WrappedBodyError(_UNCLASSIFIED_BODY))
    with pytest.raises(_WrappedBodyError):
        client.complete([{"role": "user", "content": "x"}],
                        schema_name="s", schema={"type": "object"},
                        schema_description="d")   # no timeout == not synthesis
    assert chat.calls == 1


def test_a_transient_error_body_is_still_waited_out(monkeypatch):
    # The body-aware classifier also rescues transients the wrapper hid: a 429
    # that arrives on .body behind a generic "Response validation failed" is
    # waited out across the transient budget, not given up on at the first try.
    monkeypatch.setattr(screening.time, "sleep", lambda _s: None)
    client, chat = _raising_client(lambda: _WrappedBodyError(_TRANSIENT_BODY))
    with pytest.raises(_WrappedBodyError):
        client.complete([{"role": "user", "content": "x"}],
                        schema_name="s", schema={"type": "object"},
                        schema_description="d")
    assert chat.calls == screening.MAX_TRANSIENT_ATTEMPTS
    assert client.usage.retries == screening.MAX_TRANSIENT_ATTEMPTS - 1


def test_rate_limit_is_waited_out_then_succeeds(monkeypatch, recorded_response):
    client = _correlator(recorded_response)
    good = client._client.chat
    calls = {"n": 0}

    class _FlakyChat:
        def send(self, **kwargs):
            calls["n"] += 1
            if calls["n"] < 3:
                raise RuntimeError("429 Too Many Requests")
            return good.send(**kwargs)

    client._client = type("SDK", (), {"chat": _FlakyChat()})()
    slept: list[float] = []
    monkeypatch.setattr(screening.time, "sleep", slept.append)

    parsed = client.complete(
        messages=[{"role": "user", "content": "x"}],
        schema_name="t", schema=screening.RESPONSE_SCHEMA, schema_description="d",
        max_tokens=100, pass_name="screening", label="GET /x",
    )
    assert parsed["alert_verdicts"]
    assert calls["n"] == 3
    # Backoff grows, so a ceiling that is still saturated is not hit again at
    # the same rate.
    assert len(slept) == 2 and slept[1] > slept[0]


def test_rate_limit_gives_up_after_its_budget(monkeypatch, recorded_response):
    client = _correlator(recorded_response)

    class _AlwaysLimited:
        @staticmethod
        def send(**_kwargs):
            raise RuntimeError("429 Too Many Requests")

    client._client = type("SDK", (), {"chat": _AlwaysLimited()})()
    monkeypatch.setattr(screening.time, "sleep", lambda _s: None)
    with pytest.raises(RuntimeError, match="429"):
        client.complete(messages=[{"role": "user", "content": "x"}],
                        schema_name="t", schema=screening.RESPONSE_SCHEMA,
                        schema_description="d", max_tokens=100,
                        pass_name="screening", label="GET /x")


def test_a_non_transient_error_is_not_retried(recorded_response):
    client = _correlator(recorded_response)
    calls = {"n": 0}

    class _Broken:
        @staticmethod
        def send(**_kwargs):
            calls["n"] += 1
            raise RuntimeError("400 Bad Request")

    client._client = type("SDK", (), {"chat": _Broken()})()
    with pytest.raises(RuntimeError):
        client.complete(messages=[{"role": "user", "content": "x"}],
                        schema_name="t", schema=screening.RESPONSE_SCHEMA,
                        schema_description="d", max_tokens=100,
                        pass_name="screening", label="GET /x")
    assert calls["n"] == 1


# -- cross-endpoint context (pass 1) ---------------------------------------


def _ctx_bundle(route, plugins, callees=()):
    from dast_orchestrator.analysis.join import AlertGroup, Bundle

    return Bundle(
        endpoint_key=route, match_how="seed",
        method=route.split()[0], path=route.split()[1],
        static_context={
            "path": route.split()[1],
            "ai_context": {"callees": [{"name": c, "confidence": 90} for c in callees]},
        },
        groups=[AlertGroup(plugin_id=p, name=f"rule {p}", risk="Low",
                           confidence="Medium", method=route.split()[0],
                           param="q", evidence="", urls=["http://t/x"])
                for p in plugins],
    )


def test_cross_endpoint_context_is_empty_at_level_none():
    bundles = [_ctx_bundle("GET /a", ["10031"], ["h"]),
               _ctx_bundle("GET /b", ["10031"], ["h"])]
    assert screening.build_cross_endpoint_context(bundles, "none") == {}


def test_siblings_level_counts_the_rule_without_naming_routes():
    # Naming every route carrying a rule cost ~94k prompt tokens on this target
    # and said little beyond "this rule is common", which a count says in four.
    bundles = [_ctx_bundle("GET /a", ["10031"]), _ctx_bundle("GET /b", ["10031"])]
    ctx = screening.build_cross_endpoint_context(bundles, "siblings")
    entry = ctx["GET /a"]["same_rule_elsewhere"]["10031"]
    assert entry["routes_in_this_scan"] == 2
    assert "also_on_these_routes_sharing_a_handler" not in entry
    assert "routes_sharing_a_handler" not in ctx["GET /a"]


def test_full_level_names_the_routes_that_run_the_same_handler():
    bundles = [_ctx_bundle("GET /a", ["10031"], ["repo.Home"]),
               _ctx_bundle("GET /b", ["10031"], ["repo.Home"]),
               _ctx_bundle("GET /c", ["10031"], ["other.Handler"])]
    ctx = screening.build_cross_endpoint_context(bundles, "full")
    entry = ctx["GET /a"]
    assert entry["same_rule_elsewhere"]["10031"]["routes_in_this_scan"] == 3
    # Only the route running the same code is named, not every sibling.
    assert entry["same_rule_elsewhere"]["10031"][
        "also_on_these_routes_sharing_a_handler"] == ["GET /b"]
    assert list(entry["routes_sharing_a_handler"]) == ["GET /b"]


def test_the_context_block_says_it_shows_names_only():
    # The model has not been shown those routes' code or alerts, and must not
    # assert anything about them — the confabulation shape pass 2 already hit.
    bundles = [_ctx_bundle("GET /a", ["10031"]), _ctx_bundle("GET /b", ["10031"])]
    ctx = screening.build_cross_endpoint_context(bundles, "siblings")
    assert "NOT been shown" in ctx["GET /a"]["note"]


def test_the_context_reaches_the_prompt_only_when_given():
    from dast_orchestrator.analysis.join import AlertGroup

    bundle = _ctx_bundle("GET /a", ["10031"])
    pairs = [("f-1", bundle.groups[0])]
    plain = screening.build_user_payload(bundle, pairs)
    assert "cross_endpoint_context" not in plain
    withctx = screening.build_user_payload(bundle, pairs, {"same_rule_elsewhere": {}})
    assert withctx["cross_endpoint_context"] == {"same_rule_elsewhere": {}}


# -- the verdict contract: n alerts in, n verdicts out ---------------------


def test_the_schema_pins_the_verdict_count_per_call():
    # Leaving this to the prose description cost 18-30% of every cheap-model
    # run's verdicts, with failed_calls: 0 — a short-but-valid answer is not an
    # error, so no error path could see it.
    schema = screening.verdicts_schema(6)
    verdicts = schema["properties"]["alert_verdicts"]
    assert verdicts["minItems"] == 6 and verdicts["maxItems"] == 6
    # …and the module-level schema is not mutated by building a per-call one.
    assert "minItems" not in screening.RESPONSE_SCHEMA["properties"]["alert_verdicts"]


def test_missing_verdict_ids_names_exactly_what_was_skipped():
    response = {"alert_verdicts": [{"finding_id": "f-1"}, {"finding_id": "f-3"}]}
    assert screening.missing_verdict_ids(response, ["f-1", "f-2", "f-3"]) == ["f-2"]
    assert screening.missing_verdict_ids(response, ["f-1", "f-3"]) == []
    # An empty answer means everything is missing, which the caller treats
    # differently from a partial one.
    assert screening.missing_verdict_ids({}, ["f-1"]) == ["f-1"]


# -- cost ceilings ---------------------------------------------------------


def test_a_negative_ceiling_is_no_ceiling():
    # The default everywhere: a cap that fires part-way through leaves a run
    # whose numbers are a lower bound on a question nobody asked.
    assert screening.UNLIMITED == -1.0
    assert not screening.over_budget(1_000_000.0, screening.UNLIMITED)
    assert not screening.over_budget(0.0, screening.UNLIMITED)


def test_a_ceiling_binds_once_it_is_reached():
    assert screening.over_budget(0.05, 0.05)
    assert screening.over_budget(0.06, 0.05)
    assert not screening.over_budget(0.04, 0.05)


def test_the_run_wide_ceiling_counts_what_earlier_stages_spent():
    usage = screening.LlmUsage(run_max_cost_usd=0.10, prior_cost_usd=0.08)
    assert not usage.budget_exhausted()
    usage.cost_usd = 0.02                       # this stage reaches the run cap
    assert usage.budget_exhausted()
    note = usage.budget_note()
    assert note.startswith("run cost ceiling")
    assert "0.0800" in note                     # says how much was already spent


def test_earlier_spend_is_counted_against_the_run_ceiling_once():
    """The ceiling smoke of 2026-11-02: verify could spend nothing.

    Triage had spent $1.27 of a $2.00 run ceiling. The driver subtracted that
    from the cap AND the check added it back, so verify got $2.00 - 2 x $1.27,
    below zero, and every round of its loop was refused.
    """
    usage = screening.LlmUsage(run_max_cost_usd=2.00, prior_cost_usd=1.27)
    assert usage.headroom_usd() == pytest.approx(0.73)
    usage.cost_usd = 0.72
    assert not usage.budget_exhausted()
    usage.cost_usd = 0.73
    assert usage.budget_exhausted()


def test_the_stage_ceiling_bounds_only_the_stage_own_spend():
    # Earlier stages' spend is the run ceiling's business, not this one's.
    usage = screening.LlmUsage(stage_max_cost_usd=0.10, prior_cost_usd=5.00)
    usage.cost_usd = 0.09
    assert not usage.budget_exhausted()
    usage.cost_usd = 0.10
    assert usage.budget_exhausted()
    assert usage.budget_note().startswith("stage cost ceiling")


def test_the_tightest_of_the_two_caps_binds():
    # Stage cap tighter than what the run has left.
    assert screening.headroom(0.02, 1.00, 0.10) == 0.02
    # Run cap tighter, once earlier stages are subtracted.
    assert screening.headroom(1.00, 0.30, 0.25) == pytest.approx(0.05)
    # Neither set: no ceiling at all.
    assert screening.headroom(-1, -1, 0.5) == screening.UNLIMITED


def test_a_run_already_past_its_ceiling_leaves_nothing_not_no_cap():
    # A negative remainder used to read as "no cap", so a stage after an
    # overspending one ran unbounded.
    assert screening.headroom(-1, 1.00, 1.20) == 0.0
    usage = screening.LlmUsage(run_max_cost_usd=1.00, prior_cost_usd=1.20)
    assert usage.budget_exhausted()            # refused before its first call


# -- which provider served a call -------------------------------------------

class _Endpoint:
    def __init__(self, provider, selected):
        self.provider, self.selected = provider, selected


class _Endpoints:
    def __init__(self, *eps):
        self.available = list(eps)


class _Meta:
    def __init__(self, endpoints=None, attempts=None):
        self.endpoints, self.attempts = endpoints, attempts


def test_the_serving_provider_is_read_from_the_selected_endpoint():
    """`attempts[-1].provider` was always None, so every call logged no provider.

    It cost the project cost-attribution: one model's unit price stepped 4.3x
    mid-sheet and nothing recorded which of its 14 endpoints served either half.
    """
    meta = _Meta(_Endpoints(_Endpoint("DigitalOcean", False),
                            _Endpoint("StreamLake", True),
                            _Endpoint("Atlas", False)))
    assert screening._selected_provider(meta) == "StreamLake"


def test_no_selected_endpoint_or_no_metadata_is_none_not_an_exception():
    assert screening._selected_provider(None) is None
    assert screening._selected_provider(_Meta()) is None
    assert screening._selected_provider(_Meta(_Endpoints())) is None
    assert screening._selected_provider(
        _Meta(_Endpoints(_Endpoint("X", False)))) is None


def test_build_provider_default_is_the_routing_preference():
    """Empty pin -> the throughput/require-parameters/deny/fallbacks preference."""
    pref = screening.build_provider("")
    assert pref == screening.DEFAULT_PROVIDER_PREFERENCES
    assert pref["require_parameters"] is True
    assert pref["sort"] == "throughput"
    assert pref["allow_fallbacks"] is True
    assert "only" not in pref            # not a hard pin


def test_build_provider_pin_overrides_the_preference_and_disables_fallbacks():
    """A pin hard-restricts routing and turns fallbacks off — no preference keys."""
    pinned = screening.build_provider("together")
    assert pinned == {"only": ["together"], "allow_fallbacks": False}
    assert "sort" not in pinned and "require_parameters" not in pinned


def test_build_provider_pin_accepts_a_comma_list():
    assert screening.build_provider(" together , deepinfra ")["only"] == [
        "together", "deepinfra"
    ]


def test_the_provider_preference_is_sent_on_every_call(login_bundle, pairs, recorded_response):
    """The default routing preference reaches chat.send, not just the metadata."""
    client = _correlator(recorded_response)
    client.analyse(login_bundle, pairs)
    sent = client._client.chat.last_kwargs["provider"]
    assert sent == screening.DEFAULT_PROVIDER_PREFERENCES


def test_a_hard_pin_is_what_gets_sent(login_bundle, pairs, recorded_response):
    client = _correlator(recorded_response)
    client.provider_pin = "together"
    client.provider_preference = screening.build_provider("together")
    client.analyse(login_bundle, pairs)
    assert client._client.chat.last_kwargs["provider"] == {
        "only": ["together"], "allow_fallbacks": False
    }



# -- failure details ----------------------------------------------------------


def test_a_failure_keeps_its_message_so_an_empty_arm_can_say_why():
    usage = screening.LlmUsage()
    usage.record_failure("worker_error", "GET /x: ValueError: provider returned 502")
    usage.record_failure("empty")
    d = usage.as_dict()
    assert d["failure_kinds"] == {"empty": 1, "worker_error": 1}
    assert d["failure_details"] == [
        {"kind": "worker_error", "detail": "GET /x: ValueError: provider returned 502"},
    ]


def test_a_failure_detail_is_scrubbed_truncated_and_capped():
    usage = screening.LlmUsage()
    usage.record_failure("worker_error", "Authorization: Bearer sk-or-v1-secret\n")
    assert "sk-or-v1-secret" not in usage.as_dict()["failure_details"][0]["detail"]

    usage.record_failure("not_json", "x" * 5000)
    longest = max(len(d["detail"]) for d in usage.as_dict()["failure_details"])
    assert longest == screening.MAX_FAILURE_DETAIL_CHARS

    for i in range(screening.MAX_FAILURE_DETAILS * 2):
        usage.record_failure("empty", f"call {i}")
    d = usage.as_dict()
    assert len(d["failure_details"]) == screening.MAX_FAILURE_DETAILS
    # Every failure is still counted, only the kept messages are bounded.
    assert d["failed_calls"] == screening.MAX_FAILURE_DETAILS * 2 + 2


def test_absorb_keeps_details_within_the_cap():
    a, b = screening.LlmUsage(), screening.LlmUsage()
    for i in range(screening.MAX_FAILURE_DETAILS - 1):
        a.record_failure("empty", f"a{i}")
    b.record_failure("empty", "b0")
    b.record_failure("empty", "b1")
    a.absorb(b)
    assert len(a.as_dict()["failure_details"]) == screening.MAX_FAILURE_DETAILS


def test_no_call_starts_after_the_time_limit(login_bundle, pairs, recorded_response):
    # A safety net: once it passes, every further call is refused before it is
    # sent, as its own failure kind rather than as a cost-ceiling stop.
    import time

    client = _correlator(recorded_response)
    client.usage = screening.LlmUsage(max_minutes=60, deadline=time.monotonic() - 1)
    with pytest.raises(LlmError) as raised:
        client.analyse(login_bundle, pairs)
    assert raised.value.kind == "time_limit"
    assert "60 min" in str(raised.value)
    assert client.usage.calls == 0


def test_no_time_limit_by_default():
    assert not screening.LlmUsage().out_of_time()
