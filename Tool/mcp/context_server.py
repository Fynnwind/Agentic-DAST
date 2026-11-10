"""stdio MCP server: read-only retrieval over one run's own artifacts — the pull half of
the push/pull evidence experiment.

Each tool is a thin wrapper over an existing primitive (message store, ctags index,
bounded source search) that emits WHERE things are and the raw bytes, never a MEANING;
it never writes, scans, runs a container, or calls a model. Every read is deterministic
(fixed files, same args → same bytes), and it is configured by environment
(``TRIAGE_CONTEXT_*``) because the correlator spawns it per session.
→ DECISIONS.md §"Phase: TRIAGE_RETRIEVAL=pull".
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Any

# The servers are standalone scripts outside the installed package, so make the
# package importable when run directly — the same shim `_dispatch_common` uses,
# and for the same reason: this file is both hand-runnable and required to share
# the retrieval primitives with the pipeline rather than reimplement them.
_SRC = Path(__file__).resolve().parents[1] / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from dast_orchestrator.context import code_context as cc
from dast_orchestrator.context import evidence
from dast_orchestrator.domain import verification
from mcp.server import MCPServer  # noqa: E402

#: Default text one retrieval returns, in characters — roughly 1000 tokens.
#: Enough for a response body's interesting region or a mid-sized handler, and
#: comparable to what the pushed pack spends on the same finding. Overridable
#: per session (``TRIAGE_CONTEXT_MAX_CHARS``) and per call (``max_chars``).
DEFAULT_MAX_CHARS = 4000
#: Hard ceiling on any single retrieval, session or call. ~5000 tokens: about
#: one whole pushed pack, so no single pull can cost more than the thing pull
#: mode is trying to undercut. See :meth:`RunContext.limit` for why the model is
#: allowed to reach it rather than being held at the default.
MAX_CHARS_CEILING = 20000

#: Matches one ``search_source`` call may return, and how much of each line.
#: Locations, not content: a search says *where* to look, and the caller then
#: pulls the symbol it names.
DEFAULT_SEARCH_LIMIT = 20
MAX_SEARCH_LIMIT = 100
SEARCH_LINE_CHARS = 200
#: Files larger than this are skipped by the search. A source file this big is
#: generated or vendored, and reading it would dominate the call's latency.
MAX_SEARCH_FILE_BYTES = 1_000_000

#: Extensions the source search reads. A deliberate allow-list rather than a
#: binary sniff: the search exists to look through *handler source*, and a hit
#: inside a minified asset or a fixture is noise the model would have to weigh.
SEARCH_SUFFIXES = frozenset(
    {".go", ".py", ".php", ".rb", ".js", ".ts", ".java", ".cs", ".rs", ".tmpl"}
)

srv = MCPServer("context-retrieval", version="0.1.0")


# -- what this session is serving ------------------------------------------


def _path(value: str) -> Path | None:
    value = (value or "").strip()
    return Path(value) if value else None


class RunContext:
    """The run's artifacts, opened lazily and then reused for the session.

    Lazy because a session that only ever pulls response bodies should not pay
    to parse a symbol index, and a target with no source tree should still serve
    the exchange tools. Cached because the process lives for one endpoint's
    retrieval loop and re-reading a 9 MB sidecar per call would make a pull cost
    more than the push it replaces.
    """

    def __init__(self) -> None:
        # Read with literal names, never through a helper taking the name as an
        # argument: `tests.unit.test_config` greps every getenv call site to
        # prove no variable drifts away from its declaration, and a dynamic
        # lookup is invisible to it. Cheap to keep honest, expensive to
        # rediscover.
        self.messages_path = _path(os.getenv("TRIAGE_CONTEXT_MESSAGES", ""))
        self.source_dir = _path(os.getenv("TRIAGE_CONTEXT_SOURCE", ""))
        self.index_path = _path(os.getenv("TRIAGE_CONTEXT_INDEX", ""))
        if self.index_path is None and self.source_dir is not None:
            self.index_path = cc.index_cache_path(self.source_dir)
        self._store: evidence.MessageStore | None = None
        self._index: cc.SymbolIndex | None = None
        self._index_error = ""

    @property
    def max_chars(self) -> int:
        """The session's default per-call size, from the environment."""
        try:
            value = int(os.getenv("TRIAGE_CONTEXT_MAX_CHARS", "") or DEFAULT_MAX_CHARS)
        except ValueError:
            return DEFAULT_MAX_CHARS
        return max(1, min(value, MAX_CHARS_CEILING))

    def limit(self, requested: int = 0) -> int:
        """How much this call may return: the session default unless asked.

        A caller **may ask for more**, up to :data:`MAX_CHARS_CEILING`, and that
        is deliberate. Capping every pull below what a 300-line handler needs
        would not measure "does the model pull the right things" — it would
        measure whether the cap happens to fit, and leave a symbol the model can
        see named and can never read. What bounds the cost instead is the pair
        that is actually measurable: the per-finding call budget
        (``TRIAGE_RETRIEVAL_MAX_CALLS``) and the bytes recorded for every retrieval, so
        a model that over-pulls shows up in the artifact rather than being
        quietly prevented from answering.
        """
        asked = int(requested or 0)
        if asked <= 0:
            return self.max_chars
        return max(1, min(asked, MAX_CHARS_CEILING))

    def store(self) -> "evidence.MessageStore | None":
        """The message sidecar, or ``None`` when this run has none."""
        if self._store is None:
            if self.messages_path is None or not self.messages_path.is_file():
                return None
            self._store = evidence.MessageStore.load(self.messages_path)
        return self._store

    def index(self) -> "cc.SymbolIndex | None":
        """The cached ctags index, or ``None`` with :attr:`index_error` set."""
        if self._index is None and not self._index_error:
            if self.index_path is None or not self.index_path.is_file():
                self._index_error = (
                    f"no ctags index at {self.index_path or '<unset>'} — this run "
                    "was triaged without code context, so no source is retrievable"
                )
            else:
                try:
                    self._index = cc.load_index_file(self.index_path)
                except cc.CodeContextError as exc:
                    self._index_error = str(exc)
        return self._index

    @property
    def index_error(self) -> str:
        return self._index_error

    def scope_dirs(self) -> list[Path]:
        """The directories the source search may read, from the index's scope.

        The scope is the index's own — the same ``routers/web`` the pushed pack
        was resolved from — so a pull cannot reach source the push could not.
        """
        if self.source_dir is None:
            return []
        index = self.index()
        scope = list((index.provenance.get("scope") or []) if index else [])
        if not scope:
            return [self.source_dir]
        return [self.source_dir / part for part in scope]


RUN = RunContext()


# -- the one result shape --------------------------------------------------


def retrieved(tool: str, found: bool, detail: str, **payload: Any) -> dict[str, Any]:
    """The single structure every tool returns.

    ``found=False`` is a normal answer, never an exception: "this run stored no
    body for message 47" is a *fact about the run* the model must be able to
    reason from, and a raised error would reach it as a transport failure
    instead. The caller records the same shape either way, so the artifact can
    say what was asked for and what came back.
    """
    return {"retrieved": tool, "found": found, "detail": detail, **payload}


def _cut(text: str, limit: int, offset: int = 0) -> dict[str, Any]:
    """``limit`` characters from ``offset``, and an honest account of the cut."""
    total = len(text)
    offset = max(0, min(offset, total))
    shown = text[offset:offset + limit]
    return {
        "text": shown,
        "offset": offset,
        "shown_chars": len(shown),
        "total_chars": total,
        "truncated": offset + len(shown) < total,
    }


# -- the HTTP exchange -----------------------------------------------------


def _exchange(message_id: str) -> "evidence.Exchange | None":
    store = RUN.store()
    if store is None:
        return None
    return store.exchange([str(message_id)])


_NO_SIDECAR = (
    "this run stored no message sidecar, so no HTTP exchange is retrievable — "
    "judge on the pushed pack alone"
)


@srv.tool(
    description=(
        "Return the stored HTTP response body for one ZAP message id, beyond "
        "the excerpt the prompt carried. Give `contains` to centre the window on "
        "a string (your payload, a marker), or `offset` to continue where the "
        "excerpt stopped. Raw bytes as recorded — it makes no claim about them."
    )
)
def get_response_body(
    message_id: str,
    contains: str = "",
    offset: int = 0,
    max_chars: int = 0,
) -> dict:
    """One response body, or the reason there is none.

    :param message_id: the ZAP message id, as the pushed pack reports it.
    :param contains: centre the window on the first occurrence of this string.
        Falls back to the head of the body when it does not occur, and says so.
    :param offset: character offset to read from; ignored when ``contains`` is
        given. The pushed excerpt reports the offset it stopped at.
    :param max_chars: size for this call; the session default when 0, and
        clamped to :data:`MAX_CHARS_CEILING`.
    """
    limit = RUN.limit(max_chars)
    exchange = _exchange(message_id)
    if exchange is None:
        store = RUN.store()
        return retrieved(
            "get_response_body", False,
            _NO_SIDECAR if store is None
            else f"no message {message_id!r} in this run's sidecar",
            message_id=str(message_id),
        )
    if exchange.body_omitted:
        return retrieved(
            "get_response_body", False,
            "the scan deliberately did not store a body for this exchange: no "
            "alert class citing it can be settled by one. This is NOT an empty "
            "response — nothing about the body is knowable from this run.",
            message_id=str(message_id),
        )
    if not exchange.response_body:
        return retrieved(
            "get_response_body", True,
            "the response had no body", message_id=str(message_id),
            body={"text": "", "offset": 0, "shown_chars": 0,
                  "total_chars": 0, "truncated": False},
        )

    if contains:
        # The pushed pack's own around-match excerpting, at the size this call
        # asked for — the same primitive, so a pull and a push of the same
        # region agree.
        rule = evidence.ExcerptRule(body="around-match", body_chars=limit)
        window = evidence.excerpt_body(exchange.response_body, rule, [contains])
        matched = window.get("mode") == "around-match"
        return retrieved(
            "get_response_body", True,
            f"{window['shown_chars']} of {window['total_chars']} characters, "
            + (f"centred on {contains!r} at offset {window['offset']}" if matched
               else f"from the head — {contains!r} does not occur in the body"),
            message_id=str(message_id),
            matched=matched,
            body={
                "text": window["shown"],
                "offset": window["offset"],
                "shown_chars": window["shown_chars"],
                "total_chars": window["total_chars"],
                "truncated": window["truncated"],
            },
        )

    body = _cut(exchange.response_body, limit, offset)
    return retrieved(
        "get_response_body", True,
        f"{body['shown_chars']} of {body['total_chars']} characters, from "
        f"offset {body['offset']}",
        message_id=str(message_id), body=body,
    )


@srv.tool(
    description=(
        "Return one ZAP message in full: the request line, both header blocks, "
        "the request body and the response body (bodies cut to the session's "
        "ceiling). Use it when the judgement turns on what was actually sent."
    )
)
def get_exchange(message_id: str, max_chars: int = 0) -> dict:
    """One request/response pair as recorded.

    :param message_id: the ZAP message id, as the pushed pack reports it.
    :param max_chars: size for each body in this call; the session default when
        0, and clamped to :data:`MAX_CHARS_CEILING`.
    """
    limit = RUN.limit(max_chars)
    exchange = _exchange(message_id)
    if exchange is None:
        store = RUN.store()
        return retrieved(
            "get_exchange", False,
            _NO_SIDECAR if store is None
            else f"no message {message_id!r} in this run's sidecar",
            message_id=str(message_id),
        )
    # Headers in full, bodies cut: headers are the small, decisive part for
    # every rule class, and hiding one behind a policy is what the pushed
    # `line-only` mode is for — a pull that returned less would be useless.
    rule = evidence.ExcerptRule(body="head", body_chars=limit,
                                request_headers="all", response_headers="all")
    block = evidence.excerpt_exchange(exchange, rule)
    return retrieved(
        "get_exchange", True,
        f"{exchange.method} {exchange.uri} → {exchange.status}".strip(),
        message_id=str(message_id), exchange=block,
    )


# -- the source ------------------------------------------------------------


@srv.tool(
    description=(
        "Resolve a symbol (`repo.Issues`, or a bare name) in this target's "
        "ctags index and return its source, numbered. `hops` expands into what "
        "it calls, deeper than the one hop the prompt carried. Source only — it "
        "says nothing about what the code means."
    )
)
def get_symbol_source(symbol: str, hops: int = 0, max_chars: int = 0) -> dict:
    """One symbol's definition, and optionally what it calls.

    :param symbol: the reference to resolve, written as the source writes it.
    :param hops: how far to expand into callees; ``0`` is the definition alone.
    :param max_chars: size of the returned source; the session default when 0,
        and clamped to :data:`MAX_CHARS_CEILING`.
    """
    limit = RUN.limit(max_chars)
    index = RUN.index()
    if index is None:
        return retrieved("get_symbol_source", False, RUN.index_error,
                         symbol=symbol)
    if RUN.source_dir is None or not RUN.source_dir.is_dir():
        return retrieved(
            "get_symbol_source", False,
            f"the source tree {RUN.source_dir or '<unset>'} is not present in "
            "this run, so no definition can be read",
            symbol=symbol,
        )

    blocks, unresolved = cc.extract(
        index, RUN.source_dir, [symbol],
        max_hops=max(0, int(hops or 0)), max_lines=cc.DEFAULT_MAX_LINES,
    )
    if not blocks:
        return retrieved(
            "get_symbol_source", False,
            f"the index holds no definition for {symbol!r}. It is outside the "
            f"indexed scope {index.provenance.get('scope', [])} — the standard "
            "library, or another part of the application. That is a limit of "
            "the index, not a statement that the symbol does not exist.",
            symbol=symbol, not_resolved=unresolved,
        )

    # Cut whole blocks, never a block in half: half a function body is worse
    # evidence than one fewer function, and the walk is breadth-first so what is
    # dropped is always further from the symbol that was asked for.
    # Cut whole blocks at the first one that does not fit, never a block in
    # half and never by skipping ahead to a smaller one: the walk is breadth
    # first, so a prefix of it is exactly "everything up to this distance from
    # the symbol you asked for". Taking later blocks because they happened to be
    # smaller would drop the handler body and keep three one-line helpers.
    kept: list[cc.Block] = []
    rendered: list[dict[str, Any]] = []
    dropped: list[str] = []
    used = 0
    for block in blocks:
        body = block.as_dict()
        size = len(body["source"])
        if kept and used + size > limit:
            # Named, not silently elided: the model can ask for this symbol on
            # its own, which is the whole point of being able to pull.
            dropped = [b.symbol.qualified for b in blocks[len(kept):]]
            break
        if not kept and size > limit:
            # The symbol that was actually asked for is never dropped whole: a
            # cut definition still answers "what does this handler do", and
            # returning nothing would look like an unresolvable symbol.
            body["source"] = body["source"][:limit]
            body["truncated"] = True
        kept.append(block)
        rendered.append(body)
        used += size
    result = retrieved(
        "get_symbol_source", True,
        f"{len(rendered)} definition(s), {sum(b.symbol.lines for b in kept)} "
        f"lines, from the {index.provenance.get('tool', 'ctags')} index",
        symbol=symbol, blocks=rendered,
    )
    if unresolved:
        result["not_resolved"] = unresolved
    if dropped:
        result["dropped_for_budget"] = dropped
    chain = cc.call_chain(kept)
    if chain:
        result["call_chain"] = chain
    return result


def _search_files() -> list[Path]:
    """Every searchable file in the index's scope, in a stable order."""
    files: list[Path] = []
    for root in RUN.scope_dirs():
        if not root.is_dir():
            continue
        for path in sorted(root.rglob("*")):
            if path.is_file() and path.suffix in SEARCH_SUFFIXES:
                files.append(path)
    return files


@srv.tool(
    description=(
        "Find where a literal string occurs in this target's handler tree "
        "(`ctx.FormString`, a parameter name, a function). Returns file:line "
        "locations and the matching line — WHERE, never what it means. Pull the "
        "symbol with get_symbol_source once you know where to look."
    )
)
def search_source(pattern: str, scope: str = "", limit: int = 0) -> dict:
    """A bounded literal search over the indexed source.

    :param pattern: the literal string to find. Not a regular expression: a
        retrieval tool that could be handed a catastrophic pattern would be a
        way to hang a worker, and every use this exists for is a plain string.
    :param scope: a path prefix, relative to the source tree, to narrow to. It
        is confined to the index's own scope — a pull cannot reach source the
        pushed pack could not have.
    :param limit: matches to return, clamped to :data:`MAX_SEARCH_LIMIT`.
    """
    needle = (pattern or "").strip()
    if len(needle) < 3:
        return retrieved(
            "search_source", False,
            "a search needs at least 3 characters; a shorter one matches "
            "everywhere and says nothing",
            pattern=pattern,
        )
    if RUN.source_dir is None or not RUN.source_dir.is_dir():
        return retrieved(
            "search_source", False,
            f"the source tree {RUN.source_dir or '<unset>'} is not present in "
            "this run, so there is nothing to search",
            pattern=needle,
        )
    ceiling = min(int(limit or DEFAULT_SEARCH_LIMIT), MAX_SEARCH_LIMIT)

    wanted: Path | None = None
    if scope.strip():
        candidate = (RUN.source_dir / scope.strip()).resolve()
        root = RUN.source_dir.resolve()
        if not candidate.is_relative_to(root):
            return retrieved(
                "search_source", False,
                f"scope {scope!r} is outside this target's source tree",
                pattern=needle,
            )
        wanted = candidate

    matches: list[dict[str, Any]] = []
    files_read = 0
    for path in _search_files():
        if wanted is not None and not path.resolve().is_relative_to(wanted):
            continue
        try:
            if path.stat().st_size > MAX_SEARCH_FILE_BYTES:
                continue
            text = path.read_text(errors="replace")
        except OSError:
            continue
        files_read += 1
        if needle not in text:
            continue
        for number, line in enumerate(text.splitlines(), start=1):
            if needle not in line:
                continue
            matches.append({
                "location": f"{path.relative_to(RUN.source_dir)}:{number}",
                "line": line.strip()[:SEARCH_LINE_CHARS],
            })
            if len(matches) >= ceiling:
                break
        if len(matches) >= ceiling:
            break

    return retrieved(
        "search_source", bool(matches),
        f"{len(matches)} match(es) for {needle!r} in {files_read} file(s) under "
        + (f"{scope}" if scope.strip() else
           f"{[str(p.relative_to(RUN.source_dir)) for p in RUN.scope_dirs()]}")
        + (f" — capped at {ceiling}" if len(matches) >= ceiling else ""),
        pattern=needle, matches=matches, capped=len(matches) >= ceiling,
    )


# -- the tools the pipeline can dispatch ------------------------------------


@srv.tool(
    description=(
        "What the independent verification tools this pipeline can dispatch "
        "actually do. Ask before suggesting one, so a suggestion names a "
        "capability that exists."
    )
)
def list_verification_tools() -> dict:
    """The capability block, straight from :mod:`dast_orchestrator.domain.verification`."""
    capabilities = verification.tool_capabilities()
    return retrieved(
        "list_verification_tools", True,
        f"{len(capabilities.get('tools', {}))} dispatchable tool(s)",
        **capabilities,
    )


if __name__ == "__main__":
    srv.run("stdio")
