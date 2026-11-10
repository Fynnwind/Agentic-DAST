"""Seed ZAP's site tree from an OpenAPI/Swagger document — the framework-agnostic alternative
to Noir's source extraction, for a target whose router Noir cannot model.

A spec declares routes as literal ``paths`` strings whatever the framework, so a target
points at one (served URL or committed file) and its routes seed ZAP exactly as Noir's do.
It widens discovery to the declared API surface only — not static-asset/admin routes no
spec declares, where a marker's ``--oracle seed:`` stays the honest lever — and parses into
the same :class:`~dast_orchestrator.adapters.noir_runner.SeedRequest` list, never ZAP's
opaque importer. → DECISIONS.md.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

import yaml

from dast_orchestrator.adapters import noir_runner
from dast_orchestrator.adapters.noir_runner import SeedRequest

#: HTTP methods an OpenAPI path item may declare. Anything else under a path
#: (``parameters``, ``summary``, ``$ref``, vendor extensions) is not a method.
_METHODS = ("get", "put", "post", "delete", "patch", "head", "options", "trace")


class OpenApiError(RuntimeError):
    """Raised when a declared spec cannot be fetched, parsed, or read."""


@dataclass(frozen=True)
class OpenApiSpec:
    """One declared route source: a served ``url`` XOR a committed ``file``.

    ``base_path`` overrides the prefix derived from the spec (Swagger 2.0
    ``basePath`` / OpenAPI 3.x server path) — useful when the spec's declared
    server disagrees with where the app is actually mounted for the scan.
    """

    url: str = ""
    file: str = ""
    base_path: str = ""

    def __post_init__(self) -> None:
        if bool(self.url) == bool(self.file):
            raise OpenApiError(
                "an openapi spec needs exactly one of `url` or `file`, not "
                f"both/neither (url={self.url!r}, file={self.file!r})")


def _base_path(doc: dict, override: str) -> str:
    """The path prefix every route in this spec hangs off.

    Precedence: an explicit target override, else Swagger 2.0 ``basePath``, else
    the path component of OpenAPI 3.x's first ``servers`` entry. Only the PATH is
    taken from a server url — the host is always the target's own ``base_url``,
    the same host-override ZAP's importer applies, because the spec's declared
    host is rarely the container name the scan reaches the target by.
    """
    if override:
        return "/" + override.strip("/")
    if doc.get("basePath"):
        return "/" + str(doc["basePath"]).strip("/")
    servers = doc.get("servers") or []
    if servers and isinstance(servers[0], dict) and servers[0].get("url"):
        path = urlsplit(str(servers[0]["url"])).path.strip("/")
        if path:
            return "/" + path
    return ""


def spec_paths(doc: dict, base_path_override: str = "") -> list[tuple[str, str]]:
    """``(method, path-template)`` for every operation the spec declares.

    The path templates keep their ``{param}`` placeholders; substitution into
    fetchable URLs is :func:`spec_to_seeds`'s job. A path item with no method
    keys yields nothing (a spec fragment that documents parameters but no
    operation is not a route).
    """
    if not isinstance(doc, dict):
        raise OpenApiError(f"spec is not a mapping (got {type(doc).__name__})")
    paths = doc.get("paths")
    if not isinstance(paths, dict):
        raise OpenApiError("spec declares no `paths` object")
    base = _base_path(doc, base_path_override)
    out: list[tuple[str, str]] = []
    for raw_path, item in paths.items():
        if not isinstance(item, dict):
            continue
        full = base + "/" + str(raw_path).lstrip("/")
        # Collapse a doubled slash from an empty base or a leading-slash path,
        # without touching an intentional one elsewhere in the template.
        full = "/" + full.lstrip("/")
        for method in _METHODS:
            if method in item:
                out.append((method.upper(), full))
    return out


def spec_to_seeds(doc: dict, base_url: str, path_vars: dict[str, str],
                  base_path_override: str = "",
                  source: str = "openapi") -> list[SeedRequest]:
    """Turn a parsed spec into deduplicated, fetchable seed requests.

    Path parameters are substituted with ``path_vars`` through the same
    :func:`noir_runner.substitute_path` Noir uses, so a spec-derived URL and a
    Noir-derived one are made concrete by one rule. Deduplicated on
    ``(method, url)`` because distinct templates can collapse to the same URL
    once their parameters are filled.
    """
    base = base_url.rstrip("/")
    seen: set[tuple[str, str]] = set()
    seeds: list[SeedRequest] = []
    for method, template in spec_paths(doc, base_path_override):
        concrete = noir_runner.substitute_path(template, path_vars or {})
        url = base + "/" + concrete.lstrip("/")
        key = (method, url)
        if key in seen:
            continue
        seen.add(key)
        seeds.append(SeedRequest(method, url, f"{source}:{method} {template}"))
    return seeds


def load_doc(spec: OpenApiSpec, target_dir: Path, fetch=None,
             timeout: float = 15.0) -> dict:
    """Fetch/read a spec and parse it (JSON or YAML — ``yaml.safe_load`` does both).

    :param fetch: for a ``url`` spec, the ``(method, url, timeout) -> (status,
        location, body)`` transport (e.g. :func:`auth.container_fetch` to reach a
        spec the target serves over ``dast-net``). Required for a url spec.
    :param target_dir: for a ``file`` spec, the directory it is resolved against
        (the target's own directory), so a committed spec stays with the target.
    """
    if spec.url:
        if fetch is None:
            raise OpenApiError(f"no transport to fetch spec url {spec.url!r}")
        status, _loc, body = fetch("GET", spec.url, timeout)
        if status and status >= 400:
            raise OpenApiError(f"spec url {spec.url!r} returned HTTP {status}")
        text = body
    else:
        path = (target_dir / spec.file).resolve()
        # Keep a committed spec inside the target's own directory — the same
        # containment every other per-target artifact keeps.
        if not str(path).startswith(str(target_dir.resolve())):
            raise OpenApiError(f"spec file {spec.file!r} escapes the target directory")
        if not path.is_file():
            raise OpenApiError(f"spec file not found: {path}")
        text = path.read_text()
    try:
        doc = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise OpenApiError(f"spec is not valid JSON/YAML: {exc}") from exc
    if not isinstance(doc, dict):
        raise OpenApiError("spec did not parse to a mapping")
    return doc
