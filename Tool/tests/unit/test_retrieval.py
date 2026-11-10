"""The MCP-client half of pull mode: the session, the log, and the tool loop.

Two tiers in one file, both hermetic:

* :mod:`dast_orchestrator.adapters.retrieval`'s own helpers — how a tool call is read off
  a response, how the turns are rebuilt for the provider, what the log records.
* the loop inside
  :meth:`~dast_orchestrator.analysis.screening.OpenRouterCorrelator.complete`, driven
  by a scripted fake SDK and a fake retrieval session. No subprocess, no network:
  what is under test is the *control flow* — that a tool call is executed rather
  than parsed as an answer, that the budget binds, and that push mode is
  untouched.

The live session against a real ``mcp/context_server.py`` subprocess is covered
by :mod:`tests.integration.test_retrieval_session`.
"""

from __future__ import annotations

import json

import pytest

from dast_orchestrator.analysis import screening
from dast_orchestrator.adapters import retrieval
from dast_orchestrator.analysis.screening import LlmError, OpenRouterCorrelator


# -- reading the model's tool calls ----------------------------------------

class _Call:
    def __init__(self, cid, name, arguments):
        self.id = cid
        self.type = "function"
        self.function = type("F", (), {"name": name, "arguments": arguments})()


class _Message:
    def __init__(self, content=None, tool_calls=None):
        self.content = content
        self.tool_calls = tool_calls or []
        self.reasoning = None


def test_tool_calls_are_read_with_their_arguments_parsed():
    message = _Message(tool_calls=[_Call("c1", "get_exchange", '{"message_id": "47"}')])
    [call] = retrieval.parse_tool_calls(message)
    assert call["id"] == "c1"
    assert call["name"] == "get_exchange"
    assert call["arguments"] == {"message_id": "47"}
    assert call["error"] == ""


def test_unparseable_arguments_become_an_error_not_a_dropped_call():
    """A dropped call would lose the turn; an answered one lets it correct itself."""
    message = _Message(tool_calls=[_Call("c1", "get_exchange", "{not json")])
    [call] = retrieval.parse_tool_calls(message)
    assert call["arguments"] == {}
    assert "not JSON" in call["error"]


def test_arguments_that_are_not_an_object_are_an_error():
    message = _Message(tool_calls=[_Call("c1", "get_exchange", '["47"]')])
    [call] = retrieval.parse_tool_calls(message)
    assert call["arguments"] == {} and call["error"]


def test_a_message_without_tool_calls_yields_none():
    assert retrieval.parse_tool_calls(_Message(content="{}")) == []


def test_the_assistant_turn_echoes_the_ids_the_provider_issued():
    message = _Message(tool_calls=[_Call("c1", "get_exchange", '{"message_id": "47"}')])
    calls = retrieval.parse_tool_calls(message)
    turn = retrieval.assistant_turn(message, calls)
    assert turn["role"] == "assistant"
    assert turn["tool_calls"][0]["id"] == "c1"
    assert json.loads(turn["tool_calls"][0]["function"]["arguments"]) == {
        "message_id": "47"
    }


def test_the_tool_turn_answers_the_call_it_was_given():
    turn = retrieval.tool_turn({"id": "c1"}, '{"found": true}')
    assert turn == {"role": "tool", "tool_call_id": "c1", "content": '{"found": true}'}


# -- the log ---------------------------------------------------------------

def test_the_log_records_what_was_asked_for_and_what_came_back():
    log = retrieval.RetrievalLog()
    log.record(label="GET /a", tool="get_exchange", arguments={"message_id": "47"},
               latency_ms=12.3, payload='{"found": true}', found=True, detail="ok")
    block = log.as_dict()
    assert block["calls"] == 1
    assert block["bytes_returned"] == len('{"found": true}')
    assert block["calls_by_tool"] == {"get_exchange": 1}
    # The arguments in full: what the model asked for IS the finding here.
    assert block["log"][0]["arguments"] == {"message_id": "47"}


def test_the_log_is_ordered_by_label_not_by_arrival():
    """Workers finish in any order; the artifact must not depend on which."""
    log = retrieval.RetrievalLog()
    for label in ("GET /z", "GET /a", "GET /m"):
        log.record(label=label, tool="search_source", arguments={}, latency_ms=1.0,
                   payload="{}", found=True, detail="")
    assert [e["label"] for e in log.as_dict()["log"]] == [
        "GET /a", "GET /m", "GET /z"
    ]


def test_failed_and_refused_calls_are_counted_separately():
    log = retrieval.RetrievalLog()
    log.record(label="a", tool="get_exchange", arguments={}, latency_ms=1.0,
               payload="{}", found=False, detail="boom", failed=True)
    log.note_over_budget()
    block = log.as_dict()
    assert block["calls"] == 1 and block["failed_calls"] == 1
    assert block["refused_over_budget"] == 1


# -- spawning the server ---------------------------------------------------

def test_the_server_command_carries_the_run_paths_and_no_secrets(monkeypatch):
    monkeypatch.setenv("SHARED_OPENROUTER_API_KEY", "must-not-travel")
    command = retrieval.server_command(
        messages_path="/runs/x/scan-zap-messages.json", source_dir="/targets/gitea/src",
    )
    assert command.args == [str(retrieval.SERVER_PATH)]
    assert command.env["TRIAGE_CONTEXT_MESSAGES"] == "/runs/x/scan-zap-messages.json"
    assert command.env["TRIAGE_CONTEXT_SOURCE"] == "/targets/gitea/src"
    assert "SHARED_OPENROUTER_API_KEY" not in command.env


def test_an_unknown_retrieval_mode_is_refused_by_name():
    assert retrieval.normalise_mode("") == retrieval.DEFAULT_RETRIEVAL
    assert retrieval.normalise_mode("PULL") == "pull"
    with pytest.raises(retrieval.RetrievalError, match="unknown retrieval mode"):
        retrieval.normalise_mode("psuh")


def test_an_mcp_tool_becomes_the_function_shape_chat_send_takes():
    tool = retrieval.as_function_tool(
        "get_exchange", "one message", {"type": "object", "properties": {}}
    )
    assert tool["type"] == "function"
    assert tool["function"]["name"] == "get_exchange"
    assert tool["function"]["parameters"]["type"] == "object"


# -- the loop --------------------------------------------------------------

TOOLS = [retrieval.as_function_tool("get_exchange", "one message", None)]

ANSWER = {"alert_verdicts": [{"finding_id": "f1", "needs_rescan": False,
                              "verdict": "likely-false-positive",
                              "confidence": "high", "reasoning": "r",
                              "suggested_tool": "none"}]}


class _Turn:
    """One scripted response from the SDK."""

    def __init__(self, content=None, tool_calls=None, finish_reason="stop"):
        self.choices = [type("C", (), {
            "message": _Message(content, tool_calls),
            "finish_reason": finish_reason,
        })()]
        self.usage = type("U", (), {"prompt_tokens": 10, "completion_tokens": 5,
                                    "cost": 0.0001})()
        self.model = "m/x"
        self.id = "gen-1"
        self.openrouter_metadata = None


class _ScriptedChat:
    def __init__(self, turns):
        self.turns = list(turns)
        self.sent: list[dict] = []

    def send(self, **kwargs):
        self.sent.append(kwargs)
        return self.turns.pop(0)


class _FakeSession:
    """Stands in for a stdio session: records calls, returns canned payloads."""

    def __init__(self, payload='{"found": true, "detail": "ok"}'):
        self.payload = payload
        self.calls: list[tuple[str, dict]] = []

    def call(self, tool, arguments):
        self.calls.append((tool, arguments))
        return self.payload


def _client(turns):
    client = OpenRouterCorrelator.__new__(OpenRouterCorrelator)
    client.model = screening.MODEL
    client.temperature = screening.TEMPERATURE
    client.usage = screening.LlmUsage()
    client.provider_pin = ""
    client.provider_preference = screening.build_provider("")
    client._client = type("SDK", (), {"chat": _ScriptedChat(turns)})()
    return client


def _complete(client, session=None, tools=TOOLS, max_retrievals=6):
    return client.complete(
        [{"role": "user", "content": "{}"}],
        schema_name="dast_triage", schema={"type": "object"},
        schema_description="x", require_non_empty="alert_verdicts",
        retrieval=session, retrieval_tools=tools if session else None,
        max_retrievals=max_retrievals,
    )


def test_a_tool_call_is_executed_and_the_loop_reaches_the_verdict():
    session = _FakeSession()
    client = _client([
        _Turn(tool_calls=[_Call("c1", "get_exchange", '{"message_id": "47"}')],
              finish_reason="tool_calls"),
        _Turn(content=json.dumps(ANSWER)),
    ])
    assert _complete(client, session) == ANSWER
    assert session.calls == [("get_exchange", {"message_id": "47"})]


def test_the_retrieval_turns_are_appended_in_the_order_the_provider_needs():
    session = _FakeSession()
    client = _client([
        _Turn(tool_calls=[_Call("c1", "get_exchange", "{}")],
              finish_reason="tool_calls"),
        _Turn(content=json.dumps(ANSWER)),
    ])
    _complete(client, session)
    second = client._client.chat.sent[1]["messages"]
    assert [m["role"] for m in second] == ["user", "assistant", "tool"]
    assert second[1]["tool_calls"][0]["id"] == "c1"
    assert second[2]["tool_call_id"] == "c1"


def test_every_turn_is_counted_including_the_retrieval_ones():
    """Pull's cost is the sum of its turns; counting only the answer understates it."""
    session = _FakeSession()
    client = _client([
        _Turn(tool_calls=[_Call("c1", "get_exchange", "{}")],
              finish_reason="tool_calls"),
        _Turn(content=json.dumps(ANSWER)),
    ])
    _complete(client, session)
    assert client.usage.prompt_tokens == 20
    assert client.usage.calls == 2
    assert [e["outcome"] for e in client.usage.calls_log] == ["tool_calls", "ok"]


def test_the_budget_withdraws_the_tools_and_the_model_must_answer():
    session = _FakeSession()
    client = _client([
        _Turn(tool_calls=[_Call("c1", "get_exchange", "{}")],
              finish_reason="tool_calls"),
        _Turn(content=json.dumps(ANSWER)),
    ])
    _complete(client, session, max_retrievals=1)
    assert client._client.chat.sent[0]["tools"] == TOOLS
    assert client._client.chat.sent[1]["tools"] is None
    assert len(session.calls) == 1


def test_a_call_after_the_tools_were_withdrawn_is_a_protocol_violation():
    session = _FakeSession()
    client = _client([
        _Turn(tool_calls=[_Call("c1", "get_exchange", "{}")],
              finish_reason="tool_calls"),
        _Turn(tool_calls=[_Call("c2", "get_exchange", "{}")],
              finish_reason="tool_calls"),
    ])
    with pytest.raises(LlmError) as excinfo:
        _complete(client, session, max_retrievals=1)
    assert excinfo.value.kind == "tool_loop"


def test_a_malformed_call_is_answered_with_the_error_and_still_costs_budget():
    """Otherwise a model that cannot form a call loops for free."""
    session = _FakeSession()
    client = _client([
        _Turn(tool_calls=[_Call("c1", "get_exchange", "{not json")],
              finish_reason="tool_calls"),
        _Turn(content=json.dumps(ANSWER)),
    ])
    _complete(client, session, max_retrievals=1)
    assert session.calls == []          # never executed
    assert client._client.chat.sent[1]["tools"] is None   # but budget was spent
    answered = client._client.chat.sent[1]["messages"][2]
    assert "not JSON" in answered["content"]


def test_several_calls_in_one_turn_are_all_answered():
    session = _FakeSession()
    client = _client([
        _Turn(tool_calls=[_Call("c1", "get_exchange", '{"message_id": "1"}'),
                          _Call("c2", "get_exchange", '{"message_id": "2"}')],
              finish_reason="tool_calls"),
        _Turn(content=json.dumps(ANSWER)),
    ])
    _complete(client, session)
    assert len(session.calls) == 2
    roles = [m["role"] for m in client._client.chat.sent[1]["messages"]]
    assert roles == ["user", "assistant", "tool", "tool"]


def test_push_mode_declares_no_tools_and_is_unchanged():
    """The A/B baseline: without a session, the request is what it always was."""
    client = _client([_Turn(content=json.dumps(ANSWER))])
    assert _complete(client, session=None) == ANSWER
    assert client._client.chat.sent[0]["tools"] is None
    assert len(client._client.chat.sent) == 1


def test_a_tool_call_in_push_mode_is_not_mistaken_for_an_answer():
    """No session means no loop; the response has no content, which is an error."""
    client = _client([
        _Turn(tool_calls=[_Call("c1", "get_exchange", "{}")],
              finish_reason="tool_calls"),
        _Turn(content=json.dumps(ANSWER)),
    ])
    assert _complete(client, session=None) == ANSWER
    assert [e["outcome"] for e in client.usage.calls_log] == ["empty", "ok"]


def test_the_callers_prompt_is_not_mutated_by_the_retrieval_turns():
    """`_triage_bundle` reuses a chunk when it re-asks for missing verdicts."""
    session = _FakeSession()
    client = _client([
        _Turn(tool_calls=[_Call("c1", "get_exchange", "{}")],
              finish_reason="tool_calls"),
        _Turn(content=json.dumps(ANSWER)),
    ])
    messages = [{"role": "user", "content": "{}"}]
    client.complete(messages, schema_name="t", schema={}, schema_description="x",
                    require_non_empty="alert_verdicts", retrieval=session,
                    retrieval_tools=TOOLS)
    assert messages == [{"role": "user", "content": "{}"}]


# -- what the model is offered ---------------------------------------------

def _arm(tools, monkeypatch):
    monkeypatch.setattr(retrieval, "declare_tools", lambda _c: tools)
    return retrieval.Retrieval.open(messages_path="/x/scan-zap-messages.json")


def test_a_tool_the_pack_already_pushes_is_not_offered(monkeypatch):
    """Measured: the first live pull run spent a retrieval re-fetching these."""
    arm = _arm([
        retrieval.as_function_tool("get_exchange", "d", None),
        retrieval.as_function_tool("list_verification_tools", "d", None),
    ], monkeypatch)
    assert [t["function"]["name"] for t in arm.tools] == ["get_exchange"]
    assert arm.withheld == ("list_verification_tools",)
    assert arm.as_dict()["tools_withheld_because_already_pushed"] == [
        "list_verification_tools"
    ]


def test_a_server_that_declares_nothing_fails_before_anything_is_spent(monkeypatch):
    monkeypatch.setattr(retrieval, "declare_tools", lambda _c: [])
    with pytest.raises(retrieval.RetrievalError, match="declared no tools"):
        retrieval.Retrieval.open(messages_path="/x/scan-zap-messages.json")


def test_an_unreachable_server_fails_before_anything_is_spent(monkeypatch):
    def boom(_command):
        raise OSError("no such file")
    monkeypatch.setattr(retrieval, "declare_tools", boom)
    with pytest.raises(retrieval.RetrievalError, match="did not answer"):
        retrieval.Retrieval.open(messages_path="/x/scan-zap-messages.json")


def test_the_arm_records_what_the_model_was_offered_not_just_a_count(monkeypatch):
    arm = _arm([retrieval.as_function_tool("get_exchange", "one message", None)],
               monkeypatch)
    block = arm.as_dict()
    assert block["mode"] == "pull"
    assert block["tools_declared"] == [
        {"name": "get_exchange", "description": "one message"}
    ]
    assert block["max_calls_per_finding"] == retrieval.DEFAULT_MAX_CALLS


def test_each_session_is_its_own_and_shares_only_the_log(monkeypatch):
    arm = _arm([retrieval.as_function_tool("get_exchange", "d", None)], monkeypatch)
    first, second = arm.session("a"), arm.session("b")
    assert first is not second
    assert first.log is second.log is arm.log


# -- what the first live pull runs found ------------------------------------

def test_a_bare_json_array_is_a_parse_failure_not_a_crash():
    """Measured live: `'list' object has no attribute 'get'` killed the worker."""
    client = _client([_Turn(content=json.dumps(ANSWER["alert_verdicts"])),
                      _Turn(content=json.dumps(ANSWER))])
    assert _complete(client, session=None) == ANSWER
    assert [e["outcome"] for e in client.usage.calls_log] == ["not_json", "ok"]


def test_a_malformed_answer_is_re_asked_without_the_tools():
    """Every malformed answer measured live arrived on a turn with tools on."""
    session = _FakeSession()
    client = _client([
        _Turn(tool_calls=[_Call("c1", "get_exchange", "{}")],
              finish_reason="tool_calls"),
        _Turn(content="I looked at the handler and it seems fine."),
        _Turn(content=json.dumps(ANSWER)),
    ])
    assert _complete(client, session) == ANSWER
    sent = client._client.chat.sent
    assert sent[0]["tools"] == TOOLS      # first ask: tools offered
    assert sent[1]["tools"] == TOOLS      # still offered after the retrieval
    assert sent[2]["tools"] is None       # the retry withdraws them
