"""Run OWASP Noir over a target's source tree (``targets/<name>/src/``) as a one-shot ``docker
run --rm`` to extract endpoints and per-endpoint AI context, with raw output written
unmodified.

One run (``-f json --ai-context``) yields three artifacts: the endpoint inventory
(``scan-noir-endpoints.json``), the per-endpoint AI context the LLM arm reads
(``scan-noir-ai-context.json``), and the seed map (``scan-noir-seed-map.json``) — the concrete-URL →
route-template table without which the two cannot be joined (see ``join.py``).
"""

from __future__ import annotations

import json
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import parse_qsl

from dast_orchestrator.adapters import zap_client

#: Pinned, native linux/arm64. 1.x tags carry no leading ``v`` (0.x ones did),
#: so ``v1.2.1`` does not exist. Never ``:latest``.
NOIR_IMAGE = "ghcr.io/owasp-noir/noir:1.2.1@sha256:5332bdb800dc281d4d7067aa14bd15986144f9121b92d7f466c02ba807b00103"

#: Noir also emits CLI entry points (``cli://gitea/...``); only HTTP ones are
#: meaningful to a DAST seed.
HTTP_PROTOCOL = "http"

#: Gitea's ``docs/`` tree is a Netlify site whose redirect rules Noir reports as
#: endpoints of the *docs* site. Filtered by technology because
#: ``--exclude-path`` did not suppress them.
IGNORED_TECHNOLOGIES = frozenset({"netlify"})

#: Target-neutral fallback: placeholder values live on the :class:`Target`
#: (``targets/gitea/target.yml``), and callers pass them in. This stays empty so
#: the Noir wrapper carries no knowledge of any particular target; an
#: unsubstituted placeholder falls back to :data:`FALLBACK_PATH_VAR`.
DEFAULT_PATH_VARS: dict[str, str] = {}
#: Any placeholder a caller did not supply (ids, indexes, queue ids) becomes this.
FALLBACK_PATH_VAR = "1"

#: chi's catch-all segment, replaced with a literal so the URL stays valid.
WILDCARD_REPLACEMENT = "index"

#: Key under which a catch-all's value travels in a ``path_vars`` mapping, so
#: one dictionary can carry both named placeholders and the ``*`` segment. Not a
#: legal placeholder name, so it can never collide with one.
WILDCARD_VAR = "*"

#: What a bare ``{name}`` matches when a template is read backwards: one segment.
SEGMENT_PATTERN = "[^/]+"

AI_CONTEXT_CATEGORIES = ("guards", "callees", "sources", "sinks", "validators", "signals")
AI_CONTEXT_SCHEMA_VERSION = 1
SEED_MAP_SCHEMA_VERSION = 1


class NoirError(RuntimeError):
    """Raised when Noir fails to run or returns an unexpected shape."""


@dataclass(frozen=True)
class NoirEndpoint:
    """One HTTP endpoint as Noir statically extracted it (route template form)."""

    method: str
    path: str
    technology: str
    code_paths: tuple[tuple[str, int], ...] = ()
    params: tuple[dict[str, Any], ...] = ()
    tags: tuple[dict[str, Any], ...] = ()
    ai_context: dict[str, list[dict[str, Any]]] = field(default_factory=dict)

    @property
    def key(self) -> str:
        """Stable identifier used to join Noir data to ZAP findings later."""
        return f"{self.method} {self.path}"


@dataclass(frozen=True)
class SeedRequest:
    """A concrete request ready to hand to ZAP, from Noir, a spec or an oracle seed.

    ``url`` is held in the form ZAP accepts (:func:`zap_client.zap_uri`), so the
    seed map records exactly the URL ZAP holds, whichever source built the seed.
    """

    method: str
    url: str
    endpoint_key: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "url", zap_client.zap_uri(self.url))


# -- running Noir ----------------------------------------------------------


def build_command(
    source_dir: Path,
    image: str = NOIR_IMAGE,
    use_all_taggers: bool = True,
) -> list[str]:
    """Build the one-shot ``docker run`` argv.

    Split out from :func:`run_noir` so tests can assert the invocation without a
    container, and so the writeup can quote it. Notable flags: the source mount
    is read-only (the analyser must not mutate the target), ``--ai-context``
    enriches the same JSON rather than needing a second pass, and ``--no-log``
    keeps stdout pure JSON by sending logs to stderr.
    """
    cmd = [
        "docker", "run", "--rm",
        # Without a writable HOME, Noir warns on stderr every run.
        "-e", "HOME=/tmp",
        "-v", f"{source_dir.resolve()}:/src:ro",
        image,
        "noir", "scan", "/src",
        "-f", "json",
        "--ai-context",
        "--no-color", "--no-spinner",
        "--no-log",
    ]
    if use_all_taggers:
        cmd.append("-T")
    return cmd


def run_noir(
    source_dir: Path,
    image: str = NOIR_IMAGE,
    timeout: float = 900.0,
) -> dict[str, Any]:
    """Run Noir over `source_dir` and return its parsed JSON output."""
    if not source_dir.is_dir():
        raise NoirError(
            f"Noir source tree not found: {source_dir}\n"
            "Clone the pinned target source first, e.g.\n"
            "  git clone --depth 1 --branch v1.16.0 "
            "https://github.com/go-gitea/gitea targets/gitea/src"
        )
    cmd = build_command(source_dir, image)
    try:
        proc = subprocess.run(cmd, capture_output=True, timeout=timeout)
    except FileNotFoundError as exc:  # docker not on PATH
        raise NoirError(f"could not execute docker: {exc}") from exc
    except subprocess.TimeoutExpired as exc:
        raise NoirError(f"Noir timed out after {timeout}s") from exc
    if proc.returncode != 0:
        raise NoirError(
            f"Noir exited {proc.returncode}: {proc.stderr.decode(errors='replace')[:500]}"
        )
    try:
        return json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        raise NoirError(f"Noir output was not JSON: {proc.stdout[:300]!r}") from exc


# -- parsing ---------------------------------------------------------------


def parse_endpoints(
    raw: dict[str, Any],
    ignore_technologies: "frozenset[str] | tuple[str, ...]" = (),
) -> list[NoirEndpoint]:
    """Extract the HTTP endpoints from Noir's JSON, dropping CLI/docs entries.

    :param ignore_technologies: per-target technology classifications to drop on
        top of :data:`IGNORED_TECHNOLOGIES` (e.g. WordPress passes ``php_pure``,
        Noir's file-as-endpoint fallback). Kept a parameter rather than folded
        into the module constant so the filter is a property of the target, not
        a global assumption that a framework-less PHP app could not survive.
    """
    if "endpoints" not in raw:
        raise NoirError(f"Noir output has no 'endpoints' key: {list(raw)[:5]}")

    ignored = IGNORED_TECHNOLOGIES | frozenset(ignore_technologies)
    endpoints: list[NoirEndpoint] = []
    for item in raw["endpoints"]:
        if item.get("protocol") != HTTP_PROTOCOL:
            continue
        details = item.get("details") or {}
        technology = details.get("technology", "")
        if technology in ignored:
            continue
        ai_context = {
            category: list((item.get("ai_context") or {}).get(category) or [])
            for category in AI_CONTEXT_CATEGORIES
        }
        endpoints.append(
            NoirEndpoint(
                method=(item.get("method") or "GET").upper(),
                path=item.get("url", ""),
                technology=technology,
                code_paths=tuple(
                    (cp.get("path", ""), int(cp.get("line", 0)))
                    for cp in details.get("code_paths") or []
                ),
                params=tuple(item.get("params") or []),
                tags=tuple(item.get("tags") or []),
                ai_context=ai_context,
            )
        )
    return endpoints


# -- route template -> concrete URL ----------------------------------------


def substitute_path(path: str, path_vars: dict[str, str]) -> str:
    """Replace chi placeholders in a route template with concrete values.

    Handles all three forms chi uses in Gitea's routes::

        /{username}/{reponame}                 plain named parameter
        /wiki/commit/{sha:[a-f0-9]{7,40}}      inline regex, itself containing
                                               braces — a naive regex
                                               substitution breaks here
        /template/*                            catch-all segment

    :param path_vars: placeholder name to value; unknown names fall back to
        :data:`FALLBACK_PATH_VAR`. :data:`WILDCARD_VAR` supplies the ``*``
        segment, which otherwise becomes :data:`WILDCARD_REPLACEMENT` — the
        seeding path wants a literal that keeps the URL valid, while a caller
        rebuilding a *sibling* of an observed route has the real value and
        should use it.
    """
    out: list[str] = []
    i = 0
    while i < len(path):
        char = path[i]
        if char == "{":
            depth = 1
            j = i + 1
            while j < len(path) and depth:
                if path[j] == "{":
                    depth += 1
                elif path[j] == "}":
                    depth -= 1
                j += 1
            inner = path[i + 1 : j - 1] if depth == 0 else path[i + 1 : j]
            name = inner.split(":", 1)[0].strip()
            out.append(path_vars.get(name, FALLBACK_PATH_VAR))
            i = j
        elif char == "*":
            out.append(path_vars.get(WILDCARD_VAR) or WILDCARD_REPLACEMENT)
            i += 1
        else:
            out.append(char)
            i += 1
    return "".join(out)


# Noir's go_auth tagger labels any middleware it recognises as an `auth_guard`,
# which conflates two very different things: middleware that *requires* a logged
# in user, and middleware that merely makes a session available. On Gitea every
# public route carries `sessioner`, so reading "has a guard" as "requires login"
# marks the entire public surface as protected. Both LLM passes were misled by
# this, so the distinction is drawn here, once, from the middleware name.
#
# Target-specific by nature: revisit the lists when adding WordPress/Grafana.
GUARD_ENFORCES_LOGIN = (
    "reqsignin", "requiresignin", "reqadmin", "reqowner", "reqrepoadmin",
    "reqorgmembership", "reqorgownership", "reqtoken", "reqbasicauth",
)
GUARD_IS_SESSION_PLUMBING = ("sessioner", "csrf", "cors", "securityheaders")
GUARD_EXPLICITLY_PUBLIC = ("ignsignin", "ignexplore")


def classify_guard(name: str) -> str:
    """Say whether a Noir guard actually enforces authentication.

    :param name: the guard's ``name`` field, e.g. ``"Go middleware sessioner"``.
    :returns: ``"enforces-login"``, ``"session-plumbing"``, ``"explicitly-public"``
        or ``"unknown"``. ``"unknown"`` is returned rather than guessed, because
        a wrong "protected" reading is what caused the arm to treat Gitea's whole
        public surface as authenticated.
    """
    lowered = name.lower().replace("_", "").replace(" ", "")
    for needle in GUARD_EXPLICITLY_PUBLIC:
        if needle in lowered:
            return "explicitly-public"
    for needle in GUARD_ENFORCES_LOGIN:
        if needle in lowered:
            return "enforces-login"
    for needle in GUARD_IS_SESSION_PLUMBING:
        if needle in lowered:
            return "session-plumbing"
    return "unknown"


def template_to_regex(path: str) -> re.Pattern[str]:
    """Compile a route template into a pattern that matches concrete URL paths.

    The inverse direction of `substitute_path`, needed because the spider finds
    URLs that were never seeded, so there is no recorded mapping for them.
    Placeholder handling mirrors `substitute_path` exactly:
        {name}          -> one path segment
        {name:regex}    -> the framework's own inline regex, reused verbatim so
                           `{sha:[a-f0-9]{7,40}}` keeps its precision; if it
                           does not compile in Python, fall back to a segment
        *               -> chi's catch-all, so it may span separators
    """
    out: list[str] = []
    i = 0
    while i < len(path):
        char = path[i]
        if char == "{":
            depth = 1
            j = i + 1
            while j < len(path) and depth:
                if path[j] == "{":
                    depth += 1
                elif path[j] == "}":
                    depth -= 1
                j += 1
            inner = path[i + 1 : j - 1] if depth == 0 else path[i + 1 : j]
            _, sep, pattern = inner.partition(":")
            if sep and pattern:
                try:
                    re.compile(pattern)
                    out.append(f"(?:{pattern})")
                except re.error:
                    out.append(SEGMENT_PATTERN)
            else:
                out.append(SEGMENT_PATTERN)
            i = j
        elif char == "*":
            out.append(".*")
            i += 1
        else:
            out.append(re.escape(char))
            i += 1
    return re.compile("^" + "".join(out) + "$")


def bind_path_vars(template: str, path: str) -> "dict[str, str] | None":
    """Recover the values a concrete URL supplied for a template's placeholders.

    The third direction, beside :func:`substitute_path` (template + values ->
    URL) and :func:`template_to_regex` (does this URL belong to this template?).
    It exists so a route the scanner never visited can be rebuilt from a
    *sibling* route the scanner did visit, rather than from the target's generic
    placeholder defaults.

    That distinction is the difference between a probe and a 404. The defaults
    turn ``/{username}/{reponame}/commits/tag/*`` into
    ``/thesis/demo/commits/tag/index``, a URL the target does not serve, so any
    tool aimed at it refutes for a reason that has nothing to do with the
    finding — the hazard :class:`~dast_orchestrator.stages.verify.ProbeTarget` records
    for flagged findings and the reason it never rebuilds their URLs. Binding
    the observed ``/thesis/demo/commits/branch/master/search`` against its own
    template yields ``username=thesis``, ``reponame=demo`` and ``*`` =
    ``master/search``, which rebuild the sibling as something the application
    actually routes.

    :returns: the bound values, with the catch-all under :data:`WILDCARD_VAR`,
        or ``None`` when ``path`` does not match ``template`` at all — an
        answer, not an error: the caller then falls back to the defaults.
    """
    # Numbered NAMED groups, never positional ones: an inline regex may carry
    # capture groups of its own (`{sha:([a-f0-9]{7,40})}` does), and reading
    # `match.groups()` positionally then binds `ext` to the sha. The names are
    # `_p0`, `_p1`, … rather than the placeholder names because a template may
    # repeat a placeholder, and Python rejects a duplicate group name.
    names: list[str] = []
    out: list[str] = []
    i = 0
    while i < len(template):
        char = template[i]
        if char == "{":
            depth = 1
            j = i + 1
            while j < len(template) and depth:
                if template[j] == "{":
                    depth += 1
                elif template[j] == "}":
                    depth -= 1
                j += 1
            inner = template[i + 1 : j - 1] if depth == 0 else template[i + 1 : j]
            name, sep, pattern = inner.partition(":")
            body = SEGMENT_PATTERN
            if sep and pattern:
                try:
                    re.compile(pattern)
                    body = f"(?:{pattern})"
                except re.error:
                    pass
            out.append(f"(?P<_p{len(names)}>{body})")
            names.append(name.strip())
            i = j
        elif char == "*":
            out.append(f"(?P<_p{len(names)}>.*)")
            names.append(WILDCARD_VAR)
            i += 1
        else:
            out.append(re.escape(char))
            i += 1
    try:
        match = re.compile("^" + "".join(out) + "$").match(path)
    except re.error:
        return None
    if match is None:
        return None
    # A template may name one placeholder twice; the first binding wins, which
    # is also what `substitute_path` would then write back.
    bound: dict[str, str] = {}
    for index, name in enumerate(names):
        value = match.group(f"_p{index}")
        if name and value and name not in bound:
            bound[name] = value
    return bound


def split_template_query(template: str) -> tuple[str, tuple[tuple[str, str], ...]]:
    """A route template's path, and the literal query parameters it requires.

    Noir writes a query-dispatched route with its discriminator in the template —
    WordPress's ``/wp-admin/admin-ajax.php?action=<name>`` — so the path alone
    names every action at once. The path half is what :func:`template_to_regex`
    matches; the query half is a constraint the URL must also satisfy
    (:func:`query_satisfies`). Only a ``?`` outside a ``{placeholder}`` splits,
    so an inline regex's lazy quantifier is never read as a query.

    :returns: ``(path, required)``; ``required`` is empty for a template with no
        query, which therefore matches exactly as it always did.
    """
    depth = 0
    for index, char in enumerate(template):
        if char == "{":
            depth += 1
        elif char == "}":
            depth = max(depth - 1, 0)
        elif char == "?" and depth == 0:
            query = template[index + 1:]
            return (template[:index],
                    tuple(parse_qsl(query, keep_blank_values=True)))
    return template, ()


def query_satisfies(required: Iterable[tuple[str, str]], query: str) -> bool:
    """Whether a concrete query string carries every required ``name=value`` pair.

    Extra parameters are allowed — a scanner adds its own — but a required pair
    must be present with the same value, decoded on both sides.
    """
    required = tuple(required)
    if not required:
        return True
    present = set(parse_qsl(query or "", keep_blank_values=True))
    return all(pair in present for pair in required)


def template_specificity(path: str) -> tuple[int, int, int]:
    """Rank key for choosing between templates that match the same URL.

    Collapsing templates are common in Gitea: `/org/thesis/milestones` matches
    `/org/{org}/milestones`, `/{username}/{reponame}/milestones` *and*
    `/{username}/{reponame}/{type}`. Something has to break the tie
    deterministically, or the same run would correlate differently twice.

    Sorted descending, this prefers, in order: more literal path segments, then
    fewer placeholders, then a longer literal prefix before the first
    placeholder. Callers add the endpoint key as a final tiebreak so the result
    is total.
    """
    segments = [s for s in path.split("/") if s]
    literal_segments = sum(1 for s in segments if "{" not in s and "*" not in s)
    placeholders = sum(1 for s in segments if "{" in s or "*" in s)
    literal_prefix = len(re.split(r"[{*]", path, maxsplit=1)[0])
    return (literal_segments, -placeholders, literal_prefix)


def to_seed_requests(
    endpoints: Iterable[NoirEndpoint],
    base_url: str,
    path_vars: dict[str, str] | None = None,
) -> list[SeedRequest]:
    """Turn route templates into concrete ``(method, absolute URL)`` requests.

    Deduplicated on ``(method, url)``: distinct templates can collapse onto one
    concrete URL once placeholders are substituted, and re-requesting adds run
    time without adding site-tree nodes. The *seed map* keeps the collisions —
    see :func:`build_seed_map_artifact`.
    """
    variables = {**DEFAULT_PATH_VARS, **(path_vars or {})}
    base = base_url.rstrip("/")
    seeds: list[SeedRequest] = []
    seen: set[tuple[str, str]] = set()
    for endpoint in endpoints:
        path = substitute_path(endpoint.path, variables)
        if not path.startswith("/"):
            path = "/" + path
        url = base + path
        signature = (endpoint.method, url)
        if signature in seen:
            continue
        seen.add(signature)
        seeds.append(SeedRequest(endpoint.method, url, endpoint.key))
    return seeds


def parse_path_vars(assignments: Iterable[str]) -> dict[str, str]:
    """Parse repeated `--path-var name=value` CLI arguments."""
    parsed: dict[str, str] = {}
    for assignment in assignments:
        name, sep, value = assignment.partition("=")
        if not sep or not name:
            raise NoirError(f"--path-var expects name=value, got {assignment!r}")
        parsed[name] = value
    return parsed


# -- artifacts -------------------------------------------------------------


def build_seed_map_artifact(
    endpoints: Iterable[NoirEndpoint],
    base_url: str,
    generated_at: str,
    path_vars: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Record which route templates produced which concrete URL.

    The exact half of the join: no inference, only what was actually
    substituted. Unlike :func:`to_seed_requests`, colliding templates are
    **kept** — two templates can substitute to the same URL (``org`` and
    ``username`` both resolve to ``thesis`` here) and dropping one would lose a
    legitimate correlation candidate. Deduping only ever governed which requests
    get issued, which is a separate concern.
    """
    variables = {**DEFAULT_PATH_VARS, **(path_vars or {})}
    base = base_url.rstrip("/")
    entries: dict[tuple[str, str], list[str]] = {}
    for endpoint in endpoints:
        path = substitute_path(endpoint.path, variables)
        if not path.startswith("/"):
            path = "/" + path
        entries.setdefault((endpoint.method, path), []).append(endpoint.key)
    return {
        "schema_version": SEED_MAP_SCHEMA_VERSION,
        "generated_at": generated_at,
        "base_url": base,
        "path_vars": variables,
        "entries": [
            {
                "method": method,
                "path": path,
                "url": base + path,
                "endpoint_keys": keys,
            }
            for (method, path), keys in entries.items()
        ],
    }


def build_ai_context_artifact(
    endpoints: Iterable[NoirEndpoint],
    source_dir: Path,
    generated_at: str,
    noir_image: str = NOIR_IMAGE,
) -> dict[str, Any]:
    """Distil Noir's per-endpoint AI context into the correlation-pass input.

    Shape is fixed by ``schemas/noir-ai-context.schema.json``.
    """
    return {
        "schema_version": AI_CONTEXT_SCHEMA_VERSION,
        "generated_at": generated_at,
        "noir_image": noir_image,
        "source_dir": str(source_dir),
        "endpoints": [
            {
                "key": endpoint.key,
                "method": endpoint.method,
                "path": endpoint.path,
                "technology": endpoint.technology,
                "code_paths": [
                    {"path": path, "line": line} for path, line in endpoint.code_paths
                ],
                "tags": list(endpoint.tags),
                "ai_context": endpoint.ai_context,
            }
            for endpoint in endpoints
        ],
    }


def write_artifacts(
    raw: dict[str, Any],
    endpoints: list[NoirEndpoint],
    source_dir: Path,
    out_dir: Path,
    timestamp: str,
    base_url: str,
    path_vars: dict[str, str] | None = None,
    run_id: str = "",
) -> tuple[Path, Path, Path]:
    """Write the inventory, the AI context and the seed map. Returns all paths.

    ``out_dir`` is the top-level ``data/``; the files land in this run's folder
    ``data/<run-id>/`` with stable basenames (see :mod:`run_paths`).

    :param timestamp: when the run happened — stamped *inside* the artifacts.
    :param run_id: which folder they belong to (``<timestamp>-<target>``);
        defaults to ``timestamp`` for callers that have no target name.
    """
    from dast_orchestrator.foundation.run_paths import (
        NOIR_AI_CONTEXT,
        NOIR_ENDPOINTS,
        NOIR_SEED_MAP,
        RunLayout,
    )

    layout = RunLayout(out_dir, run_id or timestamp).ensure()
    raw_path = layout.path(NOIR_ENDPOINTS)
    raw_path.write_text(json.dumps(raw, indent=2))

    ai_path = layout.path(NOIR_AI_CONTEXT)
    ai_path.write_text(
        json.dumps(
            build_ai_context_artifact(endpoints, source_dir, timestamp), indent=2
        )
    )

    seed_map_path = layout.path(NOIR_SEED_MAP)
    seed_map_path.write_text(
        json.dumps(
            build_seed_map_artifact(endpoints, base_url, timestamp, path_vars),
            indent=2,
        )
    )
    return raw_path, ai_path, seed_map_path
