"""The client half of ``TRIAGE_RETRIEVAL=pull``: hand the model a minimal pack plus the
ability to ask, and let it pull the exchange or source it wants from
``mcp/context_server.py`` (the counterpart of pushed evidence; push stays the default).

Client side only — open a session, declare its tools, execute a tool call, record every
retrieval; the loop lives in
:meth:`~dast_orchestrator.analysis.screening.OpenRouterCorrelator.complete`. Sync over
async so pass-1 concurrency stays synchronous (its determinism invariants are load-bearing):
one session per worker, opened lazily so an endpoint that asks for nothing spawns nothing.
→ DECISIONS.md.
"""

from __future__ import annotations

import json
import queue
import threading
import time
from contextlib import AsyncExitStack
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import anyio
import anyio.to_thread
from mcp import ClientSession, StdioServerParameters, stdio_client
from mcp.client.stdio import get_default_environment

REPO_ROOT = Path(__file__).resolve().parents[3]
SERVER_PATH = REPO_ROOT / "mcp" / "context_server.py"

#: How a run's prompts get their evidence.
#:
#: ``push``
#:     Today's behaviour: :class:`~dast_orchestrator.context.evidence.Assembler` attaches
#:     the full pack to every prompt. The A/B baseline, and the default.
#: ``pull``
#:     A minimal pack plus a manifest of what is retrievable; the model asks the
#:     context server for the rest.
PUSH_MODE = "push"
PULL_MODE = "pull"
RETRIEVAL_MODES = (PUSH_MODE, PULL_MODE)
DEFAULT_RETRIEVAL = PUSH_MODE

#: Retrievals one pass-1 call may make before the tools are withdrawn and the
#: model must answer with what it has. Small on purpose: the question is whether
#: a model asks for *the right* evidence, and a generous budget answers a
#: different one — an agent that pulls everything has merely rebuilt the pushed
#: pack at a higher latency. Six is enough for the exchange, the handler and a
#: search, with room to follow one of them up.
DEFAULT_MAX_CALLS = 6

#: Server tools the pushed pack **already carries**, so they are not offered to
#: the model. `list_verification_tools` is the whole list: every pass-1 payload
#: has held `verification_tools` since 2026-08-28, and the first live pull run
#: spent one of its six retrievals fetching exactly that — a round trip for
#: 2337 bytes the prompt was already carrying. The tool stays on the server, so
#: the server is still runnable by hand and complete on its own terms; what
#: changes is only what is *declared*, and the artifact records the exclusion.
ALREADY_PUSHED = ("list_verification_tools",)

#: How long one retrieval may take before the loop gives up on it. A read of
#: local files; a second is already pathological, and a worker blocked on a
#: wedged subprocess would stall the whole pass.
CALL_TIMEOUT_SECONDS = 30.0
#: How long a session may take to spawn the server and finish the MCP handshake.
#: Generous, because the first call also parses the run's message sidecar.
OPEN_TIMEOUT_SECONDS = 60.0
#: How long to wait for a session thread to wind down before leaving it to its
#: daemon fate. Nothing downstream depends on it having exited.
CLOSE_TIMEOUT_SECONDS = 10.0


class RetrievalError(RuntimeError):
    """The context server could not be reached or spoke unintelligibly."""


def server_command(
    messages_path: "Path | None" = None,
    source_dir: "Path | None" = None,
    index_path: "Path | None" = None,
    max_chars: int = 0,
    python: str = "",
) -> StdioServerParameters:
    """How to spawn the context server for one run.

    The environment is built from the MCP SDK's safe inherited set plus this
    run's four paths — **never** from ``os.environ``. The context server has no
    business holding an API key, and a subprocess that inherits the whole
    environment is the easy way for one to end up somewhere it is not wanted.
    """
    import sys

    env = get_default_environment()
    if messages_path is not None:
        env["TRIAGE_CONTEXT_MESSAGES"] = str(messages_path)
    if source_dir is not None:
        env["TRIAGE_CONTEXT_SOURCE"] = str(source_dir)
    if index_path is not None:
        env["TRIAGE_CONTEXT_INDEX"] = str(index_path)
    if max_chars:
        env["TRIAGE_CONTEXT_MAX_CHARS"] = str(int(max_chars))
    return StdioServerParameters(
        command=python or sys.executable, args=[str(SERVER_PATH)], env=env
    )


# -- declaring the server's tools to the model -----------------------------


def as_function_tool(name: str, description: str,
                     schema: "dict[str, Any] | None") -> dict[str, Any]:
    """One MCP tool in the shape ``chat.send(tools=...)`` takes.

    Plain dicts rather than the SDK's component objects: the spike (see
    ``DECISIONS.md``) established that ``ChatFunctionTool``'s function
    member *is* this dict, and keeping it literal means the writeup can quote
    what went over the wire without reading a generated class.
    """
    return {
        "type": "function",
        "function": {
            "name": name,
            "description": description or "",
            "parameters": schema or {"type": "object", "properties": {}},
        },
    }


def declare_tools(command: StdioServerParameters) -> list[dict[str, Any]]:
    """Ask the context server what it exposes, once, before the pass starts.

    The **server** is the single source of truth for the retrieval contract: its
    schemas are what the model is shown, so a tool cannot be described to the
    model in one shape and implemented in another. Done once per run rather than
    per worker because the answer is a property of the server, not of a session,
    and it belongs in the artifact as the run's retrieval provenance.
    """
    return anyio.run(_list_tools, command)


async def _list_tools(command: StdioServerParameters) -> list[dict[str, Any]]:
    async with AsyncExitStack() as stack:
        read, write = await stack.enter_async_context(stdio_client(command))
        session = await stack.enter_async_context(ClientSession(read, write))
        await session.initialize()
        listed = await session.list_tools()
        return [
            as_function_tool(tool.name, tool.description or "", tool.input_schema)
            for tool in listed.tools
        ]


# -- what was pulled -------------------------------------------------------


@dataclass
class RetrievalLog:
    """Every retrieval this run made, and what it cost.

    **Thread-safe**, for the same reason
    :class:`~dast_orchestrator.analysis.screening.LlmUsage` is: pass 1's workers all
    write here, and an unsynchronised ``+=`` silently loses increments. A count
    that is quietly short would understate exactly the thing being measured.
    """

    calls: int = 0
    failures: int = 0
    bytes_returned: int = 0
    #: Calls refused because the finding's budget was already spent.
    over_budget: int = 0
    #: One record per retrieval — see :meth:`record`.
    log: list[dict[str, Any]] = field(default_factory=list)
    _lock: "threading.Lock" = field(
        default_factory=threading.Lock, compare=False, repr=False
    )

    def record(
        self,
        *,
        label: str,
        tool: str,
        arguments: dict[str, Any],
        latency_ms: float,
        payload: str,
        found: bool,
        detail: str,
        failed: bool = False,
    ) -> None:
        """Log one call to the context server.

        ``arguments`` is stored in full: *what the model asked for* is the
        finding of this experiment, and a summary of it would answer a weaker
        question than "did it ask for the right thing".
        """
        entry = {
            "at": datetime.now(timezone.utc).isoformat(),
            "label": label,
            "tool": tool,
            "arguments": arguments,
            "latency_ms": round(latency_ms, 1),
            "bytes": len(payload),
            "found": found,
            "detail": detail[:300],
        }
        with self._lock:
            self.calls += 1
            self.bytes_returned += len(payload)
            if failed:
                self.failures += 1
            self.log.append(entry)

    def note_over_budget(self) -> None:
        with self._lock:
            self.over_budget += 1

    def as_dict(self) -> dict[str, Any]:
        """The block the artifact carries. Sorted, so it is order-independent."""
        with self._lock:
            by_tool: dict[str, int] = {}
            for entry in self.log:
                by_tool[entry["tool"]] = by_tool.get(entry["tool"], 0) + 1
            return {
                "calls": self.calls,
                "failed_calls": self.failures,
                "refused_over_budget": self.over_budget,
                "bytes_returned": self.bytes_returned,
                "calls_by_tool": dict(sorted(by_tool.items())),
                "log": sorted(self.log, key=lambda e: (e["label"], e["at"])),
            }


# -- one session -----------------------------------------------------------


class RetrievalSession:
    """A synchronous handle on one stdio session to the context server.

    Opened on the **first** call rather than on construction: an endpoint where
    the model asks for nothing must cost nothing, or the pull arm would pay a
    start-up tax that has nothing to do with what it retrieved.

    **One thread, one task, one session.** The whole session — the subprocess,
    the streams, the MCP handshake and every call — lives inside a single anyio
    task on a thread of its own, and the caller talks to it over two queues.
    That is not ceremony: anyio's cancel scopes belong to the task that entered
    them, so opening the stdio client in one task and calling from another
    (which is what a blocking portal's per-call tasks do) fails at the *first*
    retrieval with "attempted to exit a cancel scope in a different task". The
    queue hand-off is what keeps the async lifetime in one place while the
    caller stays an ordinary synchronous worker thread.

    A failed retrieval is returned as text, never raised. The model asked for
    something and has to be told what came back — including "there is no message
    47 in this run" — because that answer is itself evidence about the finding.
    A raised exception would instead lose the whole endpoint to a transport
    error.
    """

    def __init__(self, command: StdioServerParameters, log: RetrievalLog,
                 label: str = "") -> None:
        self.command = command
        self.log = log
        self.label = label
        self._thread: threading.Thread | None = None
        self._requests: "queue.Queue[Any]" = queue.Queue()
        self._replies: "queue.Queue[tuple[str, Any]]" = queue.Queue()

    def __enter__(self) -> "RetrievalSession":
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    @property
    def opened(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def _open(self) -> None:
        """Start the session thread and wait for the MCP handshake."""
        if self.opened:
            return
        self._requests = queue.Queue()
        self._replies = queue.Queue()
        thread = threading.Thread(
            target=lambda: anyio.run(self._serve),
            name=f"retrieval-{self.label or 'session'}",
            daemon=True,
        )
        thread.start()
        self._thread = thread
        state, payload = self._replies.get(timeout=OPEN_TIMEOUT_SECONDS)
        if state != "ready":
            self._thread = None
            raise RetrievalError(f"context server did not start: {payload}")

    async def _serve(self) -> None:
        """Own the session for its whole life, answering one call at a time."""
        stack = AsyncExitStack()
        try:
            read, write = await stack.enter_async_context(stdio_client(self.command))
            session = await stack.enter_async_context(ClientSession(read, write))
            await session.initialize()
        except BaseException as exc:  # noqa: BLE001 - reported to the caller
            await stack.aclose()
            self._replies.put(("error", exc))
            return
        self._replies.put(("ready", None))
        try:
            while True:
                request = await anyio.to_thread.run_sync(self._requests.get)
                if request is None:
                    break
                tool, arguments = request
                try:
                    with anyio.fail_after(CALL_TIMEOUT_SECONDS):
                        result = await session.call_tool(tool, arguments)
                except BaseException as exc:  # noqa: BLE001 - reported as an answer
                    self._replies.put(("error", exc))
                else:
                    self._replies.put(("ok", result))
        finally:
            await stack.aclose()

    def close(self) -> None:
        """Stop the session thread. Best-effort, and never fatal.

        A worker that finished its endpoint must not lose its verdicts because a
        subprocess was slow to exit, so a thread that does not stop is left to
        its daemon fate rather than joined forever.
        """
        thread, self._thread = self._thread, None
        if thread is None:
            return
        self._requests.put(None)
        thread.join(timeout=CLOSE_TIMEOUT_SECONDS)

    def call(self, tool: str, arguments: dict[str, Any]) -> str:
        """Run one retrieval and return what the model should be shown."""
        started = time.monotonic()
        try:
            self._open()
            self._requests.put((tool, arguments))
            state, payload = self._replies.get(
                timeout=CALL_TIMEOUT_SECONDS + OPEN_TIMEOUT_SECONDS
            )
            if state != "ok":
                raise RetrievalError(str(payload))
            result = payload
        except Exception as exc:
            answer = refusal(f"the context server could not answer: {exc}"[:300])
            self.log.record(
                label=self.label, tool=tool, arguments=arguments,
                latency_ms=(time.monotonic() - started) * 1000,
                payload=answer, found=False,
                detail=f"context server error: {exc}", failed=True,
            )
            return answer

        answer = _result_text(result)
        parsed = _as_json(answer)
        self.log.record(
            label=self.label, tool=tool, arguments=arguments,
            latency_ms=(time.monotonic() - started) * 1000,
            payload=answer,
            found=bool(parsed.get("found")),
            detail=str(parsed.get("detail") or ""),
            failed=bool(getattr(result, "is_error", False)),
        )
        return answer



def _result_text(result: Any) -> str:
    """The text of an MCP ``CallToolResult``, joined.

    Kept separate from :func:`_as_json` because what the *model* sees is the
    server's own text — the log parses it only to record whether the retrieval
    found anything, and a server that ever returned non-JSON must still reach
    the model verbatim rather than as a parse error.
    """
    parts = []
    for content in getattr(result, "content", []) or []:
        text = getattr(content, "text", None)
        if text:
            parts.append(text)
    return "\n".join(parts) or json.dumps(
        {"found": False, "detail": "the context server returned no content"}
    )


def _as_json(text: str) -> dict[str, Any]:
    try:
        parsed = json.loads(text)
    except (json.JSONDecodeError, TypeError):
        return {}
    return parsed if isinstance(parsed, dict) else {}


# -- reading the model's tool calls ----------------------------------------


def parse_tool_calls(message: Any) -> list[dict[str, Any]]:
    """The tool calls on one assistant message, as plain dicts.

    ``arguments`` arrives as a JSON *string* and a model can put anything in it,
    so a call whose arguments do not parse is returned with an empty mapping and
    an ``error`` rather than dropped: the loop still answers it, with the parse
    failure as the answer, which is what lets the model correct itself instead
    of silently losing a turn.
    """
    calls = []
    for call in (getattr(message, "tool_calls", None) or []):
        function = getattr(call, "function", None)
        raw = getattr(function, "arguments", "") or "{}"
        try:
            arguments = json.loads(raw)
            error = ""
        except (json.JSONDecodeError, TypeError):
            arguments, error = {}, f"arguments were not JSON: {str(raw)[:200]}"
        if not isinstance(arguments, dict):
            arguments, error = {}, f"arguments were not an object: {str(raw)[:200]}"
        calls.append({
            "id": getattr(call, "id", "") or "",
            "name": getattr(function, "name", "") or "",
            "arguments": arguments,
            "error": error,
        })
    return calls


def assistant_turn(message: Any, calls: list[dict[str, Any]]) -> dict[str, Any]:
    """The assistant message to append before the tool results.

    The provider needs the tool calls echoed back exactly as it issued them —
    ids included — or it cannot match the results to them.
    """
    return {
        "role": "assistant",
        "content": getattr(message, "content", None) or "",
        "tool_calls": [
            {
                "id": call["id"],
                "type": "function",
                "function": {
                    "name": call["name"],
                    "arguments": json.dumps(call["arguments"]),
                },
            }
            for call in calls
        ],
    }


def tool_turn(call: dict[str, Any], content: str) -> dict[str, Any]:
    return {"role": "tool", "tool_call_id": call["id"], "content": content}


@dataclass
class Retrieval:
    """Everything pull mode needs for one run, built once before the pool starts.

    The same discipline the cross-endpoint context and the evidence assembler
    already follow: what every worker shares is built up front and is read-only
    afterwards, and what a worker mutates is its own. Here the shared parts are
    the spawn command, the tool declaration and the budget; the per-worker part
    is a :class:`RetrievalSession`, handed out by :meth:`session`. The log is the
    one shared thing that *is* written to, which is why it takes a lock.
    """

    command: StdioServerParameters
    tools: list[dict[str, Any]]
    max_calls: int = DEFAULT_MAX_CALLS
    log: RetrievalLog = field(default_factory=RetrievalLog)
    #: Declared by the server and deliberately withheld — see
    #: :data:`ALREADY_PUSHED`. Recorded so a reader can see the model was not
    #: offered a tool the server has.
    withheld: tuple[str, ...] = ()

    @classmethod
    def open(
        cls,
        messages_path: "Path | None" = None,
        source_dir: "Path | None" = None,
        index_path: "Path | None" = None,
        max_calls: int = DEFAULT_MAX_CALLS,
        max_chars: int = 0,
    ) -> "Retrieval":
        """Point a run's retrieval at its artifacts and read the tool contract.

        Raises :class:`RetrievalError` if the server cannot be reached, and
        deliberately does so **before** the pass starts: a pull run whose server
        is broken must fail while nothing has been spent, not endpoint by
        endpoint after every prompt has already been paid for.
        """
        command = server_command(messages_path, source_dir, index_path, max_chars)
        try:
            tools = declare_tools(command)
        except Exception as exc:
            raise RetrievalError(
                f"the context server at {SERVER_PATH} did not answer: {exc}"
            ) from exc
        if not tools:
            raise RetrievalError(
                f"the context server at {SERVER_PATH} declared no tools, so "
                "there is nothing for the model to pull"
            )
        offered = [t for t in tools
                   if t["function"]["name"] not in ALREADY_PUSHED]
        withheld = tuple(sorted(
            t["function"]["name"] for t in tools
            if t["function"]["name"] in ALREADY_PUSHED
        ))
        return cls(command=command, tools=offered,
                   max_calls=max(0, int(max_calls)), withheld=withheld)

    def session(self, label: str = "") -> RetrievalSession:
        """One worker's own session. Costs nothing until something is pulled."""
        return RetrievalSession(self.command, self.log, label=label)

    def as_dict(self) -> dict[str, Any]:
        """The run's retrieval provenance, for the artifact.

        The declared tools are recorded by name and description, not just
        counted: what the model was *offered* is half of what "it pulled the
        right things" means, and a later reader cannot recover it from a server
        that has since changed.
        """
        return {
            "mode": PULL_MODE,
            "server": str(SERVER_PATH.name),
            "max_calls_per_finding": self.max_calls,
            "tools_declared": [
                {
                    "name": tool["function"]["name"],
                    "description": tool["function"]["description"],
                }
                for tool in self.tools
            ],
            "tools_withheld_because_already_pushed": list(self.withheld),
            **self.log.as_dict(),
        }


def refusal(reason: str) -> str:
    return json.dumps({"found": False, "detail": reason})


def index_path_for(source_dir: "Path | None") -> "Path | None":
    """Where the run's ctags index lives, if the target has a source tree."""
    if source_dir is None:
        return None
    from dast_orchestrator.context import code_context as cc

    path = cc.index_cache_path(source_dir)
    return path if path.is_file() else None


def normalise_mode(value: str) -> str:
    mode = (value or "").strip().lower() or DEFAULT_RETRIEVAL
    if mode not in RETRIEVAL_MODES:
        raise RetrievalError(
            f"unknown retrieval mode {value!r}; expected one of "
            f"{', '.join(RETRIEVAL_MODES)}"
        )
    return mode

