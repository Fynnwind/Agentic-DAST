"""A real stdio session to a real ``mcp/context_server.py`` subprocess.

The unit tier stubs the session away to test the loop's control flow; this tier
is the boundary itself — the subprocess, the MCP handshake, the tool schemas and
the bytes coming back — because that boundary is where this project's bugs have
actually been. No model and no network: the server reads a fixture run directory
built in ``tmp_path``.

The concurrency test is the load-bearing one. Pass 1's workers each open their
own session, and the invariant that a concurrent run's result is identical to a
sequential one is what pull mode must not break.
"""

from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from dast_orchestrator.adapters import retrieval

HANDLER = """package repo

func Issues(ctx *context.Context) {
\tkeyword := ctx.FormString("q")
\t_ = keyword
}
"""


@pytest.fixture
def served(tmp_path: Path):
    """A fixture run directory and the command that serves it."""
    messages = {
        "counts": {"messages": 1},
        "messages": {
            "47": {
                "id": "47",
                "request_header": "GET http://t/x?q=1 HTTP/1.1\r\nhost: t\r\n",
                "request_body": "",
                "response_header": "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n",
                "response_body": "<p>reflected: " + "z" * 200 + "</p>",
            },
        },
    }
    (tmp_path / "scan-zap-messages.json").write_text(json.dumps(messages))
    source = tmp_path / "src"
    (source / "routers" / "web" / "repo").mkdir(parents=True)
    (source / "routers" / "web" / "repo" / "issue.go").write_text(HANDLER)
    (tmp_path / "ctags-index.json").write_text(json.dumps({
        "provenance": {"tool": "universal-ctags", "version": "6.1.0",
                       "scope": ["routers/web"], "languages": ["Go"]},
        "symbols": [{"name": "Issues", "package": "repo",
                     "path": "routers/web/repo/issue.go", "start": 3, "end": 6,
                     "kind": "func", "signature": "(ctx *context.Context)"}],
    }))
    return retrieval.server_command(
        messages_path=tmp_path / "scan-zap-messages.json",
        source_dir=source,
        index_path=tmp_path / "ctags-index.json",
    )


def test_the_server_declares_its_five_tools_with_usable_schemas(served):
    tools = retrieval.declare_tools(served)
    names = {tool["function"]["name"] for tool in tools}
    assert names == {"get_response_body", "get_exchange", "get_symbol_source",
                     "search_source", "list_verification_tools"}
    schema = next(t for t in tools
                  if t["function"]["name"] == "get_response_body")["function"]
    assert schema["description"]
    assert "message_id" in schema["parameters"]["properties"]


def test_a_session_opens_only_when_something_is_actually_pulled(served):
    """An endpoint the model asks nothing of must cost nothing."""
    log = retrieval.RetrievalLog()
    with retrieval.RetrievalSession(served, log, label="GET /x") as session:
        assert session.opened is False
    assert log.calls == 0


def test_a_pull_returns_the_server_s_own_payload_and_is_logged(served):
    log = retrieval.RetrievalLog()
    with retrieval.RetrievalSession(served, log, label="GET /x") as session:
        answer = json.loads(session.call("get_exchange", {"message_id": "47"}))
    assert answer["found"] is True
    assert answer["exchange"]["status"] == 200
    [entry] = log.as_dict()["log"]
    assert entry["tool"] == "get_exchange"
    assert entry["arguments"] == {"message_id": "47"}
    assert entry["bytes"] > 0 and entry["found"] is True


def test_several_pulls_reuse_the_one_session(served):
    log = retrieval.RetrievalLog()
    with retrieval.RetrievalSession(served, log, label="GET /x") as session:
        session.call("get_symbol_source", {"symbol": "repo.Issues"})
        session.call("search_source", {"pattern": "FormString"})
        assert session.opened is True
    assert log.as_dict()["calls_by_tool"] == {
        "get_symbol_source": 1, "search_source": 1
    }


def test_an_unknown_tool_is_answered_not_raised(served):
    """The model has to be told; a raised error would lose the whole endpoint."""
    log = retrieval.RetrievalLog()
    with retrieval.RetrievalSession(served, log, label="GET /x") as session:
        answer = session.call("no_such_tool", {})
    assert isinstance(answer, str) and answer
    assert log.as_dict()["failed_calls"] == 1


def test_a_server_that_cannot_start_degrades_to_an_answer(tmp_path):
    log = retrieval.RetrievalLog()
    broken = retrieval.server_command(python="/nonexistent/python")
    with retrieval.RetrievalSession(broken, log, label="GET /x") as session:
        answer = json.loads(session.call("get_exchange", {"message_id": "47"}))
    assert answer["found"] is False
    assert log.as_dict()["failed_calls"] == 1


def test_concurrent_sessions_return_identical_bytes(served):
    """Each worker gets its own session; the result must not depend on the pool."""
    def pull(worker: int) -> str:
        log = retrieval.RetrievalLog()
        with retrieval.RetrievalSession(served, log, label=f"w{worker}") as session:
            return session.call("get_symbol_source", {"symbol": "repo.Issues"})

    with ThreadPoolExecutor(max_workers=4) as pool:
        answers = list(pool.map(pull, range(4)))
    assert len(set(answers)) == 1
    assert json.loads(answers[0])["found"] is True
