"""The read-only retrieval tools of ``mcp/context_server.py``.

Like :mod:`tests.unit.test_wrappers`, the server lives outside the installed
package, so the test adds ``mcp/`` to the path and imports it directly and calls
the tool functions themselves — what is under test is the retrieval, not MCP's
transport.

Everything runs against a **fixture run directory** built in ``tmp_path``: a
small message sidecar, a two-file source tree and a hand-written ctags index.
No model, no network, no Docker, no ctags — which is the point, because a
retrieval tool that needed any of those would not be the deterministic read of
fixed artifacts the pull experiment rests on.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

WRAPPER_DIR = Path(__file__).resolve().parents[2] / "mcp"
sys.path.insert(0, str(WRAPPER_DIR))

import context_server as ctx  # noqa: E402

HANDLER = """package repo

func Issues(ctx *context.Context) {
\tkeyword := ctx.FormString("q")
\tissues(ctx, keyword)
}

func issues(ctx *context.Context, keyword string) {
\tctx.Data["Keyword"] = keyword
}
"""

OTHER = """package admin

func Config(ctx *context.Context) {
\tctx.Data["Mode"] = ctx.FormString("mode")
}
"""

BODY = "<html><head><title>Home</title></head><body>" + ("x" * 500) + "MARKER" + ("y" * 500) + "</body></html>"


@pytest.fixture
def run_dir(tmp_path: Path) -> Path:
    """A minimal finished run: a sidecar, a source tree and its ctags index."""
    messages = {
        "schema_version": 1,
        "counts": {"messages": 3},
        "messages": {
            "1": {
                "id": "1",
                "request_header": "GET http://t/repo/issues?q=abc HTTP/1.1\r\nhost: t\r\n",
                "request_body": "",
                "response_header": "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n",
                "response_body": BODY,
            },
            "2": {
                "id": "2",
                "request_header": "GET http://t/static/app.css HTTP/1.1\r\nhost: t\r\n",
                "request_body": "",
                "response_header": "HTTP/1.1 200 OK\r\nContent-Type: text/css\r\n",
                "response_body_omitted": "no alert class citing this message "
                                         "can be settled by a body",
            },
            "3": {
                "id": "3",
                "request_header": "HEAD http://t/ HTTP/1.1\r\nhost: t\r\n",
                "request_body": "",
                "response_header": "HTTP/1.1 204 No Content\r\n",
                "response_body": "",
            },
        },
    }
    (tmp_path / "scan-zap-messages.json").write_text(json.dumps(messages))

    source = tmp_path / "src"
    (source / "routers" / "web" / "repo").mkdir(parents=True)
    (source / "routers" / "web" / "admin").mkdir(parents=True)
    (source / "routers" / "web" / "repo" / "issue.go").write_text(HANDLER)
    (source / "routers" / "web" / "admin" / "admin.go").write_text(OTHER)
    # Outside the indexed scope: nothing may reach it.
    (source / "models").mkdir()
    (source / "models" / "issue.go").write_text('const Secret = "FormString"\n')

    index = {
        "provenance": {
            "tool": "universal-ctags", "version": "6.1.0",
            "scope": ["routers/web"], "languages": ["Go"],
        },
        "symbols": [
            {"name": "Issues", "package": "repo",
             "path": "routers/web/repo/issue.go", "start": 3, "end": 6,
             "kind": "func", "signature": "(ctx *context.Context)"},
            {"name": "issues", "package": "repo",
             "path": "routers/web/repo/issue.go", "start": 8, "end": 10,
             "kind": "func", "signature": "(ctx *context.Context, keyword string)"},
            {"name": "Config", "package": "admin",
             "path": "routers/web/admin/admin.go", "start": 3, "end": 5,
             "kind": "func", "signature": "(ctx *context.Context)"},
        ],
    }
    (tmp_path / "ctags-index.json").write_text(json.dumps(index))
    return tmp_path


@pytest.fixture
def served(run_dir, monkeypatch):
    """Point the module-level :data:`context_server.RUN` at the fixture run."""
    def install(**env: str):
        monkeypatch.setenv("TRIAGE_CONTEXT_MESSAGES",
                           str(run_dir / "scan-zap-messages.json"))
        monkeypatch.setenv("TRIAGE_CONTEXT_SOURCE", str(run_dir / "src"))
        for key, value in env.items():
            monkeypatch.setenv(key, value)
        monkeypatch.setattr(ctx, "RUN", ctx.RunContext())
        return run_dir
    return install


@pytest.fixture
def unconfigured(monkeypatch):
    """A session told about no run at all — the degraded case."""
    for var in ("TRIAGE_CONTEXT_MESSAGES", "TRIAGE_CONTEXT_SOURCE",
                "TRIAGE_CONTEXT_INDEX", "TRIAGE_CONTEXT_MAX_CHARS"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setattr(ctx, "RUN", ctx.RunContext())


# -- get_response_body -----------------------------------------------------

def test_body_is_returned_with_an_honest_account_of_the_cut(served):
    served()
    out = ctx.get_response_body("1", max_chars=100)
    assert out["found"] is True
    assert out["body"]["shown_chars"] == 100
    assert out["body"]["total_chars"] == len(BODY)
    assert out["body"]["truncated"] is True


def test_body_offset_continues_where_the_excerpt_stopped(served):
    served()
    out = ctx.get_response_body("1", offset=44, max_chars=10)
    assert out["body"]["text"] == BODY[44:54]
    assert out["body"]["offset"] == 44


def test_body_contains_centres_the_window_on_the_match(served):
    served()
    out = ctx.get_response_body("1", contains="MARKER", max_chars=100)
    assert out["matched"] is True
    assert "MARKER" in out["body"]["text"]
    assert out["body"]["offset"] > 0


def test_body_contains_that_does_not_occur_falls_back_and_says_so(served):
    served()
    out = ctx.get_response_body("1", contains="nowhere-in-this-body")
    assert out["found"] is True
    assert out["matched"] is False
    assert "does not occur" in out["detail"]


def test_an_omitted_body_is_not_an_empty_one(served):
    """The distinction the whole sidecar policy exists to preserve."""
    served()
    out = ctx.get_response_body("2")
    assert out["found"] is False
    assert "NOT an empty response" in out["detail"]
    assert "body" not in out


def test_a_genuinely_empty_body_is_found_and_empty(served):
    served()
    out = ctx.get_response_body("3")
    assert out["found"] is True
    assert out["body"]["total_chars"] == 0


def test_unknown_message_id_is_a_finding_not_an_exception(served):
    served()
    out = ctx.get_response_body("999")
    assert out["found"] is False
    assert "999" in out["detail"]


def test_without_a_sidecar_the_exchange_tools_say_so(unconfigured):
    out = ctx.get_response_body("1")
    assert out["found"] is False
    assert "no message sidecar" in out["detail"]


def test_a_call_may_not_exceed_the_hard_ceiling(served):
    served()
    out = ctx.get_response_body("1", max_chars=10_000_000)
    assert out["body"]["shown_chars"] <= ctx.MAX_CHARS_CEILING


def test_the_session_default_applies_when_a_call_asks_for_nothing(served):
    served(TRIAGE_CONTEXT_MAX_CHARS="50")
    assert ctx.get_response_body("1")["body"]["shown_chars"] == 50


# -- get_exchange ----------------------------------------------------------

def test_exchange_carries_both_header_blocks_in_full(served):
    served()
    out = ctx.get_exchange("1", max_chars=20)
    exchange = out["exchange"]
    assert out["found"] is True
    assert exchange["request_line"] == "GET http://t/repo/issues?q=abc"
    assert exchange["status"] == 200
    assert "host: t" in exchange["request_headers"]
    assert "Content-Type: text/html" in exchange["response_headers"]
    # Headers whole, body cut: the header is the small decisive part.
    assert exchange["response_body"]["shown_chars"] == 20


# -- get_symbol_source -----------------------------------------------------

def test_symbol_resolves_to_numbered_source(served):
    served()
    out = ctx.get_symbol_source("repo.Issues")
    assert out["found"] is True
    [block] = out["blocks"]
    assert block["symbol"] == "repo.Issues"
    assert block["location"] == "routers/web/repo/issue.go:3-6"
    assert "FormString" in block["source"]
    assert block["source"].startswith("3  ")


def test_hops_expand_into_what_the_symbol_calls(served):
    served()
    out = ctx.get_symbol_source("repo.Issues", hops=1)
    assert [b["symbol"] for b in out["blocks"]] == ["repo.Issues", "repo.issues"]
    assert out["call_chain"] == ["repo.Issues -> repo.issues"]


def test_hops_default_to_the_definition_alone(served):
    served()
    assert len(ctx.get_symbol_source("repo.Issues")["blocks"]) == 1


def test_a_budget_cut_names_what_it_dropped(served):
    """Breadth first, so a prefix is kept and the rest is named, never elided."""
    served()
    out = ctx.get_symbol_source("repo.Issues", hops=1, max_chars=60)
    assert [b["symbol"] for b in out["blocks"]] == ["repo.Issues"]
    assert out["dropped_for_budget"] == ["repo.issues"]


def test_an_unresolvable_symbol_blames_the_index_scope(served):
    served()
    out = ctx.get_symbol_source("models.Issue")
    assert out["found"] is False
    assert "outside the indexed scope" in out["detail"]
    assert "routers/web" in out["detail"]


def test_without_an_index_the_source_tools_say_why(served, run_dir):
    (run_dir / "ctags-index.json").unlink()
    served()
    out = ctx.get_symbol_source("repo.Issues")
    assert out["found"] is False
    assert "no ctags index" in out["detail"]


# -- search_source ---------------------------------------------------------

def test_search_reports_locations_and_the_matching_line(served):
    served()
    out = ctx.search_source("FormString")
    assert out["found"] is True
    locations = [m["location"] for m in out["matches"]]
    assert "routers/web/repo/issue.go:4" in locations
    assert "routers/web/admin/admin.go:4" in locations


def test_search_is_confined_to_the_indexed_scope(served):
    """A pull may not reach source the pushed pack could not have."""
    served()
    out = ctx.search_source("FormString")
    assert not any(m["location"].startswith("models/") for m in out["matches"])


def test_search_scope_narrows_within_the_indexed_tree(served):
    served()
    out = ctx.search_source("FormString", scope="routers/web/admin")
    assert [m["location"] for m in out["matches"]] == [
        "routers/web/admin/admin.go:4"
    ]


def test_search_refuses_a_scope_outside_the_source_tree(served):
    served()
    out = ctx.search_source("FormString", scope="../../../etc")
    assert out["found"] is False
    assert "outside this target's source tree" in out["detail"]


def test_search_refuses_a_pattern_too_short_to_mean_anything(served):
    served()
    out = ctx.search_source("q")
    assert out["found"] is False
    assert "at least 3 characters" in out["detail"]


def test_search_caps_its_matches_and_says_it_capped(served):
    served()
    out = ctx.search_source("ctx", limit=1)
    assert len(out["matches"]) == 1
    assert out["capped"] is True


def test_search_is_deterministic_across_calls(served):
    """The determinism the concurrent pass depends on, asserted rather than assumed."""
    served()
    first = ctx.search_source("FormString")
    second = ctx.search_source("FormString")
    assert first == second


def test_search_without_a_source_tree_says_so(unconfigured):
    out = ctx.search_source("FormString")
    assert out["found"] is False
    assert "not present in this run" in out["detail"]


# -- list_verification_tools ----------------------------------------------

def test_capabilities_come_from_the_verification_module(served):
    served()
    from dast_orchestrator.domain import verification

    out = ctx.list_verification_tools()
    assert out["found"] is True
    assert set(out["tools"]) == set(verification.tool_capabilities()["tools"])


# -- the shape every tool shares -------------------------------------------

@pytest.mark.parametrize("call", [
    lambda: ctx.get_response_body("1"),
    lambda: ctx.get_exchange("1"),
    lambda: ctx.get_symbol_source("repo.Issues"),
    lambda: ctx.search_source("FormString"),
    lambda: ctx.list_verification_tools(),
])
def test_every_tool_returns_the_one_shape(served, call):
    served()
    out = call()
    assert out["retrieved"] and isinstance(out["found"], bool) and out["detail"]
