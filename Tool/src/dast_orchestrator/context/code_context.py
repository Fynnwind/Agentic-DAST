"""The scoped code extractor: resolve a finding's handler symbol to real source.

Noir's ``--ai-context`` names a callee's reference site, not its definition, so the chain is
Noir scopes → universal-ctags locates → we read: a ctags symbol index gives the exact
function extent and one bounded same-package hop reaches the flagged parameter. Its rule:
structure that says WHERE things are is cheap and safe, what things MEAN belongs to the
model — so it emits raw source plus non-semantic navigation and never synthesises
``sinks``/``validators`` (that is SAST, kept as the independent Semgrep baseline).
→ DECISIONS.md.
"""

from __future__ import annotations

import json
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

from dast_orchestrator.foundation import ui

REPO_ROOT = Path(__file__).resolve().parents[3]

#: Built from ``docker/ctags/Dockerfile``; see there for why this project builds
#: its own rather than pulling one. Both halves of the pin (base image tag and
#: apk package version) live in that file.
CTAGS_IMAGE = "dast-ctags:6.1.0"
CTAGS_VERSION = "6.1.0"

#: ctags fields the extractor depends on: ``n`` line number, ``e`` **end line**,
#: ``K`` kind name, ``S`` signature. ``end:`` is the one that removes the need
#: for a parser — it is the exact extent of the definition.
CTAGS_FIELDS = "+neKS"

#: Version of the cached index's shape; bumped when :class:`Symbol` gains a
#: field, so a cache written before it is rebuilt rather than read short.
INDEX_FORMAT = 2

#: Levels of :data:`CODE_CONTEXT_LEVELS`, selectable per run.
#:
#: ``none``
#:     No handler source at all — the shape of an early, ungrounded run,
#:     kept as the A/B baseline rather than as a fallback.
#: ``handler``
#:     The resolved handler plus its hop bodies, raw.
#: ``handler+trace``
#:     The same handler source plus the non-semantic navigation (the "trace"):
#:     the call chain that was followed, and where the flagged parameter
#:     literally appears in it.
CODE_CONTEXT_LEVELS = ("none", "handler", "handler+trace")
#: Defaults to ``handler+trace``: its measured value is source-grounded refutation
#: of the table's false positives, agreeing with independent tool verification.
#: Degrades to ``none`` with a
#: warning on a target with no ``code_context`` scope or source tree, so an
#: unprepared target still runs.
DEFAULT_CODE_CONTEXT = "handler+trace"

#: Ceiling on how far a hop expansion walks, and on how much source one finding
#: may carry. The measured saturation makes both generous rather than binding on
#: this target; they exist for a target whose handler tree is not so cleanly
#: separated from the rest of its source.
DEFAULT_MAX_HOPS = 1
DEFAULT_MAX_LINES = 600


class CodeContextError(RuntimeError):
    """Raised when the symbol index cannot be built or read."""


# -- the index -------------------------------------------------------------


@dataclass(frozen=True)
class Symbol:
    """One definition, located. No interpretation of any kind."""

    name: str
    package: str
    path: str
    start: int
    end: int
    kind: str = ""
    signature: str = ""
    #: The class a method is defined in, as ctags' ``class:`` field names it
    #: (``WPDM\Package\PackageLocks``); empty for a free function and for
    #: every Go symbol, which ctags scopes by ``package:`` instead.
    scope: str = ""

    @property
    def qualified(self) -> str:
        if self.scope:
            return f"{self.scope}::{self.name}"
        return f"{self.package}.{self.name}" if self.package else self.name

    @property
    def location(self) -> str:
        return f"{self.path}:{self.start}-{self.end}"

    @property
    def lines(self) -> int:
        return max(self.end - self.start + 1, 0)


def build_command(
    source_dir: Path,
    scope: Sequence[str],
    languages: Sequence[str],
    kinds: Mapping[str, str],
    image: str = CTAGS_IMAGE,
) -> list[str]:
    """The exact ``docker run`` that produces the index.

    A function rather than YAML, for the same reason ``noir_runner`` builds its
    Noir invocation in Python: the command is part of what a run is, and it has
    to be readable next to the code that interprets its output.

    ``--network none`` because a symbol index is a pure read of a mounted tree,
    and the whole point of building the image was that nothing is fetched at run
    time.
    """
    args = [
        "docker", "run", "--rm", "--platform", "linux/arm64", "--network", "none",
        "-v", f"{source_dir.resolve()}:/src:ro",
        image,
        "ctags", "-f", "-", f"--fields={CTAGS_FIELDS}", "--recurse=yes",
    ]
    if languages:
        args.append("--languages=" + ",".join(languages))
    for language, letters in sorted(kinds.items()):
        args.append(f"--kinds-{language}={letters}")
    args.extend(scope or ["."])
    return args


_TAG_RE = re.compile(
    r"^(?P<name>[^\t]+)\t(?P<path>[^\t]+)\t(?P<rest>.*)$"
)


#: End line a symbol carries when ctags did not emit ``end:`` for it, so
#: :func:`backfill_extents` can tell "ctags gave the extent" from "it did not".
#: A real definition never starts at line 0, so 0 is unambiguous.
UNKNOWN_END = 0


def parse_tags(text: str) -> list[Symbol]:
    """Parse ctags' own output format.

    Deliberately tolerant on two axes. A line with no ``line:`` field is skipped
    (there is nothing to locate). A line with ``line:`` but no ``end:`` is
    **kept**, with ``end`` set to :data:`UNKNOWN_END`: some ctags parsers do not
    compute a scope end at all — the PHP parser is one, and dropping every one of
    its symbols would leave a whole language with an empty index. Those symbols'
    extents are filled in afterwards by :func:`backfill_extents`; a language ctags
    parses less completely must degrade to *coarser* symbols, never to none.
    """
    symbols: list[Symbol] = []
    for line in text.splitlines():
        if not line or line.startswith("!_TAG_"):
            continue
        match = _TAG_RE.match(line)
        if not match:
            continue
        # ``rest`` is the ex_cmd (a line number or a ``/^…$/;"`` search pattern),
        # then the bare kind name, then ``key:value`` extension fields. The
        # ex_cmd is dropped by position rather than by pattern: it is free text
        # from the source line and can contain anything, colons included.
        parts = match.group("rest").split("\t")[1:]
        fields: dict[str, str] = {}
        kind = ""
        for part in parts:
            key, sep, value = part.partition(":")
            if sep:
                fields[key] = value
            elif part.strip():
                kind = kind or part.strip()
        try:
            start = int(fields["line"])
        except (KeyError, ValueError):
            continue
        try:
            end = int(fields["end"])
        except (KeyError, ValueError):
            end = UNKNOWN_END
        symbols.append(
            Symbol(
                name=match.group("name"),
                package=fields.get("package", ""),
                path=match.group("path"),
                start=start,
                end=end,
                kind=fields.get("kind", kind),
                signature=fields.get("signature", ""),
                # ctags escapes a backslash in a field value as `\\`.
                scope=fields.get("class", "").replace("\\\\", "\\"),
            )
        )
    return symbols


def backfill_extents(symbols: Sequence[Symbol], source_dir: Path) -> list[Symbol]:
    """Give every :data:`UNKNOWN_END` symbol an extent, without a language parser.

    Some ctags parsers (PHP among them) locate a definition's start but never its
    end. The extent is recovered the only non-semantic way there is: a
    definition runs until the next definition in the same file begins. The
    symbols of one file, sorted by start line, therefore partition it, and each
    unknown-ended symbol takes the line before its successor's start; the last
    symbol in a file runs to end-of-file. Trailing blank lines are trimmed so the
    block ends on real source.

    This is an **approximation and is only applied where ctags gave nothing** —
    a symbol that already has an ``end:`` (Go, C, JS) is returned untouched, so
    the exact-extent guarantee those languages had is unchanged. Its
    imprecision is bounded and in the safe direction: it can attribute a few
    trailing comment/blank lines between two definitions to the earlier one, but
    the extractor's line budget already caps how much source a finding carries,
    and it never crosses into an unrelated definition.

    Nesting is the one case it coarsens: a closure or nested function defined
    inside another (rare in the handler code this indexes) would end the outer
    symbol early. That is acceptable for a WHERE-not-WHAT locator and is the
    price of not shipping a per-language brace lexer.
    """
    by_file: dict[str, list[Symbol]] = {}
    for symbol in symbols:
        by_file.setdefault(symbol.path, []).append(symbol)

    filled: list[Symbol] = []
    for path, group in by_file.items():
        group.sort(key=lambda s: (s.start, s.end))
        line_count = _line_count(source_dir / path)
        for i, symbol in enumerate(group):
            if symbol.end and symbol.end >= symbol.start:
                filled.append(symbol)
                continue
            # The next definition that starts strictly after this one bounds it;
            # symbols sharing a start line (a rarity) do not bound each other.
            boundary = line_count
            for later in group[i + 1:]:
                if later.start > symbol.start:
                    boundary = later.start - 1
                    break
            end = _trim_trailing_blanks(source_dir / path, symbol.start, boundary)
            filled.append(Symbol(
                name=symbol.name, package=symbol.package, path=symbol.path,
                start=symbol.start, end=max(end, symbol.start),
                kind=symbol.kind, signature=symbol.signature, scope=symbol.scope,
            ))
    return filled


def _line_count(path: Path) -> int:
    try:
        return len(path.read_text(errors="replace").splitlines())
    except OSError:
        return 0


def _trim_trailing_blanks(path: Path, start: int, end: int) -> int:
    """Pull ``end`` back past blank lines between two definitions, 1-indexed."""
    try:
        lines = path.read_text(errors="replace").splitlines()
    except OSError:
        return end
    end = min(end, len(lines))
    while end > start and not lines[end - 1].strip():
        end -= 1
    return end


class SymbolIndex:
    """Name -> definition. A dict lookup, built once per source tree version."""

    def __init__(self, symbols: Iterable[Symbol],
                 provenance: Mapping[str, Any] | None = None) -> None:
        self.symbols = list(symbols)
        self.provenance = dict(provenance or {})
        self._by_qualified: dict[str, list[Symbol]] = {}
        self._by_name: dict[str, list[Symbol]] = {}
        for symbol in self.symbols:
            self._by_qualified.setdefault(symbol.qualified, []).append(symbol)
            self._by_name.setdefault(symbol.name, []).append(symbol)
        #: Every package the index knows. Used to tell "a package outside this
        #: index" (``http``, ``path``, ``log``) from "an import alias for one
        #: inside it" — see :func:`callees`.
        self.packages = {s.package for s in self.symbols if s.package}

    def __len__(self) -> int:
        return len(self.symbols)

    def is_unique(self, name: str) -> bool:
        return len(self._by_name.get(name, ())) == 1

    def named(self, name: str) -> list[Symbol]:
        """Every definition called ``name``, whatever its package or class."""
        return list(self._by_name.get(name, ()))

    def resolve(self, reference: str,
                prefer_package: str = "") -> Symbol | None:
        """Locate ``repo.Issues``, or a bare ``issues`` within a package.

        Ambiguity is resolved by preferring the caller's own package and then by
        source location, never at random: Gitea has an ``Action`` in both
        ``repo`` and ``user``, and a chain that resolved differently on two runs
        would make the same finding carry different code on each.
        """
        reference = (reference or "").strip()
        if not reference:
            return None
        bare = reference.rpartition(".")[2]
        candidates = self._by_qualified.get(reference)
        if not candidates and "." in reference:
            package = reference.rpartition(".")[0]
            candidates = [
                s for s in self._by_name.get(bare, []) if s.package == package
            ]
        if not candidates:
            # By bare name — never by the dotted reference, which is not a key
            # in this map. Getting that wrong silently cost every import-aliased
            # handler its source (Gitea's `user_setting.*`, 17 endpoints) while
            # the alias rule that was supposed to catch them looked correct.
            pool = self._by_name.get(bare, [])
            same = [s for s in pool if s.package == prefer_package]
            candidates = same or pool
        if not candidates:
            return None
        return sorted(candidates, key=lambda s: (s.path, s.start))[0]


def index_cache_path(source_dir: Path) -> Path:
    """Beside the source it indexes: it is valid for a *source tree version*."""
    return source_dir.parent / "ctags-index.json"


def _source_revision(source_dir: Path) -> str:
    """The checked-out commit, when the source tree is a git clone.

    Cheaper and more honest than hashing 1515 files: the index is valid for a
    source tree version, and a shallow clone of a tag already states which.
    """
    try:
        result = subprocess.run(
            ["git", "-C", str(source_dir), "rev-parse", "HEAD"],
            capture_output=True, text=True, timeout=20, check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return ""
    return result.stdout.strip() if result.returncode == 0 else ""


def build_index(
    source_dir: Path,
    scope: Sequence[str],
    languages: Sequence[str] = (),
    kinds: Mapping[str, str] | None = None,
    image: str = CTAGS_IMAGE,
    timeout: float = 300.0,
) -> SymbolIndex:
    """Run ctags once over the scoped tree."""
    command = build_command(source_dir, scope, languages, kinds or {}, image)
    try:
        result = subprocess.run(
            command, capture_output=True, text=True, timeout=timeout, check=False,
        )
    except FileNotFoundError as exc:
        raise CodeContextError(f"docker not available: {exc}") from exc
    except subprocess.TimeoutExpired as exc:
        raise CodeContextError(f"ctags timed out after {timeout}s") from exc
    if result.returncode != 0:
        raise CodeContextError(
            f"ctags exited {result.returncode}: {result.stderr.strip()[:400]}\n"
            f"(build the image once: docker build --platform linux/arm64 "
            f"-t {image} docker/ctags)"
        )
    symbols = backfill_extents(parse_tags(result.stdout), source_dir)
    return SymbolIndex(
        symbols,
        {
            "tool": "universal-ctags",
            "version": CTAGS_VERSION,
            "image": image,
            "command": command,
            "scope": list(scope),
            "languages": list(languages),
            "source_dir": str(source_dir),
            "source_revision": _source_revision(source_dir),
            "symbols": len(symbols),
            "index_format": INDEX_FORMAT,
        },
    )


def load_index_file(path: Path) -> SymbolIndex:
    """Read one cached index file. Never builds, so it needs no Docker.

    Split out from :func:`load_or_build_index` for the read-only context MCP
    server, which serves a run's *already built* index and must not shell out to
    ctags: a retrieval tool that could rebuild an index would no longer be a
    deterministic read of fixed artifacts. Keeping the parse here means the
    cache's shape is known in exactly one place.

    :raises CodeContextError: the file is absent or not a readable index.
    """
    try:
        data = json.loads(path.read_text())
        return SymbolIndex(
            (Symbol(**s) for s in data.get("symbols", [])),
            data.get("provenance") or {},
        )
    except (OSError, ValueError, TypeError) as exc:
        raise CodeContextError(f"unreadable ctags index {path}: {exc}") from exc


def load_or_build_index(
    source_dir: Path,
    scope: Sequence[str],
    languages: Sequence[str] = (),
    kinds: Mapping[str, str] | None = None,
    image: str = CTAGS_IMAGE,
    refresh: bool = False,
) -> SymbolIndex:
    """The cached index for this source tree, building it if it is stale.

    Cached because it only changes when the source does, and the source of a
    pinned target never changes. The cache records the revision and the scope it
    was built for, and is rebuilt when either moves — a cache keyed on nothing
    would quietly serve one target version's symbols for another's.
    """
    cache = index_cache_path(source_dir)
    wanted = {
        "source_revision": _source_revision(source_dir),
        "scope": list(scope),
        "languages": list(languages),
        "version": CTAGS_VERSION,
        "index_format": INDEX_FORMAT,
    }
    if cache.is_file() and not refresh:
        try:
            index = load_index_file(cache)
            stored = index.provenance
            if all(stored.get(k) == v for k, v in wanted.items()):
                return index
        except CodeContextError as exc:
            ui.warn(f"ignoring unreadable ctags cache {cache.name}: {exc}")

    index = build_index(source_dir, scope, languages, kinds, image)
    try:
        cache.write_text(json.dumps(
            {
                "provenance": index.provenance,
                "symbols": [vars(s) for s in index.symbols],
            },
            indent=1,
        ))
    except OSError as exc:
        ui.warn(f"could not cache the ctags index: {exc}")
    return index


# -- reading the source ----------------------------------------------------


@dataclass(frozen=True)
class Block:
    """One definition's source, and how the walk arrived at it."""

    symbol: Symbol
    text: str
    depth: int
    reached_from: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "symbol": self.symbol.qualified,
            "location": self.symbol.location,
            "signature": self.symbol.signature,
            "depth": self.depth,
            **({"called_from": self.reached_from} if self.reached_from else {}),
            "source": self.text,
        }


def read_block(source_dir: Path, symbol: Symbol) -> str:
    """The exact lines ``end:`` delimits, numbered.

    Numbered because every other part of the pack refers to source by
    ``file:line`` — the Noir signals, the parameter sites, the call chain — and
    a model asked to cite a line it was shown without line numbers can only
    guess at one.
    """
    path = source_dir / symbol.path
    try:
        lines = path.read_text(errors="replace").splitlines()
    except OSError:
        return ""
    start = max(symbol.start - 1, 0)
    selected = lines[start:symbol.end]
    width = len(str(symbol.end))
    return "\n".join(
        f"{symbol.start + offset:>{width}}  {line}"
        for offset, line in enumerate(selected)
    )


#: A call site, qualified (``repo.Issues(``) or bare (``issues(``). Matching
#: calls rather than every identifier keeps the walk to things that are actually
#: invoked, which is what "one hop" is supposed to mean.
_CALL_RE = re.compile(r"\b(?:(?P<pkg>[A-Za-z_]\w*)\.)?(?P<name>[A-Za-z_]\w*)\s*\(")


def resolve_reference(index: SymbolIndex, reference: str,
                      package: str = "") -> Symbol | None:
    """One reference, under the package rules :func:`callees` documents.

    Shared with the root resolution in :func:`extract` on purpose: Noir's
    ``callees`` names are written the way the source writes them, aliases
    included, so a root and a hop have to be resolved by the same rule or the
    aliased handlers would resolve one hop in and never as an entry point.
    """
    symbol = index.resolve(reference, prefer_package=package)
    if symbol is None:
        return None
    pkg, _, name = reference.rpartition(".")
    if not pkg:
        return symbol if not package or symbol.package == package else None
    if symbol.package == pkg:
        return symbol
    if pkg not in index.packages and index.is_unique(name):
        return symbol
    return None


def callees(text: str, index: SymbolIndex, package: str) -> list[Symbol]:
    """Definitions in the index that this block calls, in first-appearance order.

    The resolution rule is Go's own and carries no judgement: an **unqualified**
    call is same-package, so only a same-package symbol may satisfy it; a
    **qualified** call names its package, so only that package's symbol may.
    Without that rule a bare ``Error(...)`` would pull in whichever ``Error``
    the index happened to sort first, and the finding would carry source it has
    nothing to do with.

    The one relaxation is Go's import aliases — Gitea writes
    ``user_setting.AvatarPost`` for ``routers/web/user/setting``, whose ctags
    package is ``setting`` — and it is admitted only when the qualifier names no
    package the index holds (so it is an alias, or an outside package like
    ``http``) **and** the bare name is unique in the index (so nothing is being
    chosen between candidates). Both halves are required: without the second, a
    call into stdlib would resolve to whatever local symbol shared its name.
    """
    found: dict[str, Symbol] = {}
    for match in _CALL_RE.finditer(text):
        pkg, name = match.group("pkg"), match.group("name")
        reference = f"{pkg}.{name}" if pkg else name
        symbol = resolve_reference(index, reference, package)
        if symbol is not None:
            found.setdefault(symbol.qualified, symbol)
    return list(found.values())


def extract(
    index: SymbolIndex,
    source_dir: Path,
    roots: Sequence[str],
    max_hops: int = DEFAULT_MAX_HOPS,
    max_lines: int = DEFAULT_MAX_LINES,
) -> tuple[list[Block], list[str]]:
    """Walk from Noir's named symbols outward, breadth first.

    :param roots: the callee names Noir scoped this endpoint to, e.g.
        ``["repo.Issues"]``.
    :returns: the blocks, and the names that could not be resolved. Unresolved
        names are returned rather than dropped: "Noir named a symbol this index
        does not contain" is a fact about the scope of the index, and silently
        omitting it would make a thin context indistinguishable from a small one.
    """
    seeds: list[Symbol] = []
    unresolved: list[str] = []
    seen: set[str] = set()
    for root in roots:
        symbol = resolve_reference(index, root)
        if symbol is None:
            unresolved.append(root)
            continue
        if symbol.qualified not in seen:
            seen.add(symbol.qualified)
            seeds.append(symbol)
    blocks, walk_unresolved = _walk(index, source_dir, seeds, max_hops, max_lines)
    return blocks, unresolved + walk_unresolved


def extract_from_symbols(
    index: SymbolIndex,
    source_dir: Path,
    seeds: Sequence[Symbol],
    max_hops: int = DEFAULT_MAX_HOPS,
    max_lines: int = DEFAULT_MAX_LINES,
) -> tuple[list[Block], list[str]]:
    """The bounded walk from symbols already located — e.g. by a registration."""
    return _walk(index, source_dir, seeds, max_hops, max_lines)


def _walk(
    index: SymbolIndex,
    source_dir: Path,
    seeds: Sequence[Symbol],
    max_hops: int,
    max_lines: int,
) -> tuple[list[Block], list[str]]:
    """Breadth-first source walk from already-resolved seed symbols.

    Shared by :func:`extract` (seeds from Noir's callee names) and
    :func:`extract_from_paths` (seeds from the handler file Noir located, for an
    endpoint it named no callees for). One hop out follows each block's own
    callees; the line budget bounds the whole walk.
    """
    blocks: list[Block] = []
    unresolved: list[str] = []
    seen: set[str] = set()
    budget = max_lines

    frontier: list[tuple[Symbol, int, str]] = []
    for symbol in seeds:
        if symbol.qualified not in seen:
            seen.add(symbol.qualified)
            frontier.append((symbol, 0, ""))

    while frontier:
        symbol, depth, parent = frontier.pop(0)
        if symbol.lines > budget:
            # Breadth-first, so what is dropped here is always further from the
            # handler than what was kept. Reported in the context block rather
            # than silently elided.
            unresolved.append(f"{symbol.qualified} (over the {max_lines}-line budget)")
            continue
        text = read_block(source_dir, symbol)
        if not text:
            unresolved.append(f"{symbol.qualified} (source unreadable)")
            continue
        blocks.append(Block(symbol, text, depth, parent))
        budget -= symbol.lines
        if depth >= max_hops:
            continue
        for callee in _block_callees(text, index, symbol, source_dir):
            if callee.qualified in seen:
                continue
            seen.add(callee.qualified)
            frontier.append((callee, depth + 1, symbol.qualified))
    return blocks, unresolved


def index_relative_path(path: str) -> str:
    """A Noir ``code_paths`` path, relative to ``source_dir`` like the index.

    Noir analyses the tree mounted at ``/src``, so it reports ``/src/<rel>``,
    while the ctags index keys files by ``<rel>`` (relative to ``source_dir``).
    Only that single mount segment is Noir's; a target whose own tree nests — a
    plugin under ``src/`` — keeps its nesting (``/src/src/Admin/X.php`` ->
    ``src/Admin/X.php``).
    """
    rel = path.lstrip("/")
    if rel.startswith("src/"):
        rel = rel[len("src/"):]
    return rel


_index_relative_path = index_relative_path


def symbols_in_file(index: SymbolIndex, rel_path: str, line: int = 0) -> list[Symbol]:
    """The index's symbols defined in ``rel_path``.

    With a 1-indexed ``line``, the single smallest symbol whose body encloses it
    — the handler the line sits in; without one (Noir reports ``0`` when it has
    only a file), every symbol the file defines, left for the walk's line budget
    to trim. Empty when the file is outside the index's scope.
    """
    in_file = [s for s in index.symbols if s.path == rel_path]
    if not in_file:
        return []
    if line > 0:
        enclosing = [s for s in in_file if s.start <= line <= (s.end or s.start)]
        if enclosing:
            return [sorted(enclosing, key=lambda s: (s.lines, s.start))[0]]
    return sorted(in_file, key=lambda s: (s.start, s.name))


def extract_from_paths(
    index: SymbolIndex,
    source_dir: Path,
    code_paths: Sequence[tuple[str, int]],
    max_hops: int = DEFAULT_MAX_HOPS,
    max_lines: int = DEFAULT_MAX_LINES,
) -> tuple[list[Block], list[str]]:
    """Resolve handler source from the FILE Noir located, not its callee names.

    The fallback for an endpoint Noir gave a ``code_paths`` entry but no
    ``callees`` for — a framework whose request dispatch Noir cannot follow to a
    named call (WordPress's hook actions, among others). The handler file is
    known, so the walk is seeded from the symbols that file defines. Same budget
    and one-hop callee follow as :func:`extract`; the trace is thinner because
    the entry point came from a file rather than a named call, which is why this
    is a fallback and not the primary path.

    :param code_paths: ``(path, line)`` pairs from Noir's ``code_paths``; a
        ``line`` of ``0`` means the file is known but not the definition line.
    """
    seeds: list[Symbol] = []
    unresolved: list[str] = []
    seen: set[str] = set()
    for path, line in code_paths:
        found = symbols_in_file(index, index_relative_path(path), line)
        if not found:
            unresolved.append(f"{path} (no symbol in the indexed scope)")
            continue
        for symbol in found:
            if symbol.qualified not in seen:
                seen.add(symbol.qualified)
                seeds.append(symbol)
    blocks, walk_unresolved = _walk(index, source_dir, seeds, max_hops, max_lines)
    return blocks, unresolved + walk_unresolved


# -- PHP ------------------------------------------------------------------


_OPEN_TAG = re.compile(r"<\?(?:php\b|=)?", re.I)
_HEREDOC = re.compile(r"""<<<[ \t]*(['"]?)([A-Za-z_]\w*)\1\r?\n""")


def strip_php_comments(text: str, start_in_php: bool = False) -> str:
    """``text`` reduced to PHP code: comments and inline HTML blanked, strings kept.

    Blanks ``//``, ``#`` and ``/* */`` comments and everything outside
    ``<?php … ?>``, and steps over heredoc bodies, so an apostrophe in a comment,
    a template or a heredoc never opens a phantom string. Blanked characters
    become spaces and newlines stay: every offset and line number is unchanged.

    :param start_in_php: treat the text as already inside ``<?php`` — for a
        definition's body, which carries no open tag of its own.
    """
    out = list(text)
    size = len(text)

    def blank(start: int, end: int) -> None:
        for j in range(start, min(end, size)):
            if out[j] != "\n":
                out[j] = " "

    i = 0
    quote = ""
    in_php = start_in_php
    while i < size:
        if not in_php:
            tag = _OPEN_TAG.search(text, i)
            end = tag.start() if tag else size
            blank(i, end)
            if tag is None:
                break
            i, in_php = tag.end(), True
            continue
        char = text[i]
        nxt = text[i + 1] if i + 1 < size else ""
        if quote:
            if char == "\\":
                i += 2
                continue
            if char == quote:
                quote = ""
            i += 1
        elif char in ("'", '"'):
            quote = char
            i += 1
        elif char == "<" and text.startswith("<<<", i):
            heredoc = _HEREDOC.match(text, i)
            if heredoc is None:
                i += 3
                continue
            closing = re.compile(rf"^[ \t]*{re.escape(heredoc.group(2))}\b", re.M)
            found = closing.search(text, heredoc.end())
            i = found.end() if found else size
        elif char == "?" and nxt == ">":
            in_php = False
            i += 2
        elif char == "#" or (char == "/" and nxt == "/"):
            start = i
            while i < size and text[i] != "\n" and not text.startswith("?>", i):
                i += 1
            blank(start, i)
        elif char == "/" and nxt == "*":
            end = text.find("*/", i + 2)
            end = size if end < 0 else end + 2
            blank(i, end)
            i = end
        else:
            i += 1
    return "".join(out)


def php_names(text: str) -> tuple[str, dict[str, str]]:
    """A PHP file's ``namespace`` and its ``use`` imports (alias -> full name)."""
    namespace = ""
    match = re.search(r"^\s*namespace\s+([\w\\]+)\s*[;{]", text, re.M)
    if match:
        namespace = match.group(1).strip("\\")
    uses: dict[str, str] = {}
    for use in re.finditer(r"^\s*use\s+([\w\\]+)(?:\s+as\s+(\w+))?\s*;", text, re.M):
        full = use.group(1).strip("\\")
        uses[use.group(2) or full.rsplit("\\", 1)[-1]] = full
    return namespace, uses


def class_candidates(name: str, namespace: str, uses: dict[str, str]) -> list[str]:
    """Full class names ``name`` may mean in a file, most likely first."""
    name = name.strip()
    if name.startswith("\\"):
        return [name.strip("\\")]
    head, _, rest = name.partition("\\")
    out: list[str] = []
    if head in uses:
        out.append(uses[head] + (f"\\{rest}" if rest else ""))
    if namespace:
        out.append(f"{namespace}\\{name}")
    out.append(name)
    return list(dict.fromkeys(out))


def find_method(index: SymbolIndex, method: str,
                classes: Sequence[str]) -> Symbol | None:
    """``method`` defined on the first of ``classes`` that defines it.

    Falls back to the class's short name only when exactly one indexed class of
    that short name defines the method — never a choice between candidates.
    """
    defined = [s for s in index.named(method) if s.scope]
    for full in classes:
        exact = [s for s in defined if s.scope == full]
        if exact:
            return sorted(exact, key=lambda s: (s.path, s.start))[0]
    shorts = {c.rsplit("\\", 1)[-1] for c in classes}
    by_short = [s for s in defined if s.scope.rsplit("\\", 1)[-1] in shorts]
    return by_short[0] if len(by_short) == 1 else None


def find_function(index: SymbolIndex, name: str) -> Symbol | None:
    """A free (class-less) function named ``name``, only when it is unique."""
    found = [s for s in index.named(name) if not s.scope]
    return found[0] if len(found) == 1 else None


#: Files whose definitions are PHP, so the walk reads their calls by PHP's rules.
PHP_SUFFIXES = (".php", ".inc", ".phtml")

#: Language constructs a ``name(`` pattern would otherwise read as calls.
_PHP_CONSTRUCTS = frozenset({
    "if", "elseif", "else", "while", "for", "foreach", "switch", "match", "catch",
    "array", "list", "isset", "empty", "unset", "eval", "exit", "die", "echo",
    "print", "return", "include", "include_once", "require", "require_once",
    "function", "fn", "new", "clone", "declare", "and", "or", "xor", "use",
})
_PHP_CALL_RE = re.compile(r"(?<![\w$\\])([A-Za-z_]\w*)\s*\(")
#: The ``  12  `` prefix :func:`read_block` puts on every line it returns.
_BLOCK_LINE_NUMBER = re.compile(r"^ *\d+  ", re.M)


def php_callees(text: str, index: SymbolIndex, symbol: Symbol,
                source_dir: Path) -> list[Symbol]:
    """Definitions a PHP block calls, by PHP's own receiver rules, in order.

    * ``$this->m()``, ``self::m()``, ``static::m()`` — ``m`` on the block's own class;
    * ``X::m()`` — ``m`` on class ``X``, read through the file's namespace and
      ``use`` imports (:func:`class_candidates`);
    * ``$obj->m()`` — only when exactly one definition anywhere is named ``m``;
    * ``f()`` — a free function, only when it is unique.

    ``parent::`` calls and constructors are not followed, and nothing is ever
    chosen between candidates: an ambiguous call resolves to nothing.
    """
    try:
        file_text = (source_dir / symbol.path).read_text(errors="replace")
    except OSError:
        file_text = ""
    namespace, uses = php_names(file_text)
    code = strip_php_comments(_BLOCK_LINE_NUMBER.sub("", text), start_in_php=True)
    found: dict[str, Symbol] = {}
    for match in _PHP_CALL_RE.finditer(code):
        name = match.group(1)
        if name.lower() in _PHP_CONSTRUCTS:
            continue
        before = code[max(0, match.start() - 160):match.start()].rstrip()
        target: Symbol | None = None
        if before.endswith("->"):
            receiver = before[:-2].rstrip().rstrip("?")
            if receiver.endswith("$this"):
                target = (find_method(index, name, [symbol.scope])
                          if symbol.scope else None)
            else:
                named = index.named(name)
                target = named[0] if len(named) == 1 else None
        elif before.endswith("::"):
            receiver_match = re.search(r"(\\?[\w\\]+)$", before[:-2].rstrip())
            receiver = receiver_match.group(1) if receiver_match else ""
            if receiver.lower() in ("self", "static"):
                target = (find_method(index, name, [symbol.scope])
                          if symbol.scope else None)
            elif receiver and receiver.lower() != "parent":
                target = find_method(index, name,
                                     class_candidates(receiver, namespace, uses))
        elif re.search(r"\b(?:function|new)\s*&?$", before, re.I):
            continue
        else:
            target = find_function(index, name)
        if target is not None and target.qualified != symbol.qualified:
            found.setdefault(target.qualified, target)
    return list(found.values())


def _block_callees(text: str, index: SymbolIndex, symbol: Symbol,
                   source_dir: Path) -> list[Symbol]:
    """A block's callees under its own language's rules (PHP, else Go's)."""
    if symbol.path.endswith(PHP_SUFFIXES):
        return php_callees(text, index, symbol, source_dir)
    return callees(text, index, symbol.package)


# -- non-semantic navigation ----------------------------------------------


def parameter_sites(blocks: Iterable[Block], parameter: str,
                    limit: int = 8) -> list[dict[str, Any]]:
    """Where the flagged parameter literally appears in the included source.

    A string search, not an analysis — and it does most of the attention work
    over 300 lines of handler. ZAP says the parameter is ``labels``; this points
    at ``issue.go:149``, ``selectLabels := ctx.FormString("labels")``. It makes
    no claim about what happens to the value there, which is exactly the line
    between what this module may compute and what the model must decide.
    """
    needle = (parameter or "").strip()
    if len(needle) < 2:
        return []
    sites: list[dict[str, Any]] = []
    for block in blocks:
        for numbered in block.text.splitlines():
            number, _, code = numbered.partition("  ")
            if needle not in code:
                continue
            sites.append({
                "location": f"{block.symbol.path}:{number.strip()}",
                "in_symbol": block.symbol.qualified,
                "line": code.strip()[:200],
            })
            if len(sites) >= limit:
                return sites
    return sites


def call_chain(blocks: Iterable[Block]) -> list[str]:
    """``repo.Issues -> issues`` for each edge the walk actually followed."""
    return [
        f"{block.reached_from} -> {block.symbol.qualified}"
        for block in blocks if block.reached_from
    ]


def build_context(
    index: SymbolIndex,
    source_dir: Path,
    roots: Sequence[str],
    parameter: str = "",
    level: str = "handler+trace",
    max_hops: int = DEFAULT_MAX_HOPS,
    max_lines: int = DEFAULT_MAX_LINES,
) -> dict[str, Any] | None:
    """The ``handler_source`` block an evidence pack carries, or ``None``.

    :param level: ``none`` returns ``None`` — the A/B baseline. ``source``
        returns the blocks alone; ``handler+trace`` adds the call chain and the
        parameter sites.
    """
    if level == "none" or not roots:
        return None
    blocks, unresolved = extract(index, source_dir, roots, max_hops, max_lines)
    if not blocks:
        return {
            "scoped_by": list(roots),
            "resolved": [],
            "not_resolved": unresolved,
            "note": "Noir scoped this endpoint to the symbols above and the "
                    "index holds a definition for none of them, so no handler "
                    "source is attached. This is a limit of the index's scope, "
                    "not a statement that the handler is empty.",
        }
    context: dict[str, Any] = {
        "scoped_by": list(roots),
        "index": {
            "tool": f"universal-ctags {index.provenance.get('version', '')}",
            "scope": index.provenance.get("scope", []),
            "symbols": len(index),
        },
        "blocks": [block.as_dict() for block in blocks],
        "lines_included": sum(b.symbol.lines for b in blocks),
    }
    if unresolved:
        context["not_resolved"] = unresolved
    if level == "handler+trace":
        chain = call_chain(blocks)
        if chain:
            context["call_chain"] = chain
        sites = parameter_sites(blocks, parameter)
        context["parameter_sites"] = sites if sites else []
        context["navigation_note"] = (
            "`call_chain` and `parameter_sites` are navigation, not analysis: "
            "the chain is which definitions were followed, and the sites are a "
            "plain string search for the flagged parameter name. Neither says "
            "anything about whether the value is validated, escaped or reaches "
            "a sink -- that judgement is yours, from the source above."
        )
    return context
