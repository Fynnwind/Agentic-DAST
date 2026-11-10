"""Validate a ``data/`` artifact against its JSON Schema (``Tool/schemas/*.schema.json``)
where a stage reads it, so a truncated or wrong-shaped artifact fails with a named field
rather than a KeyError deep in a stage.

Policy by result: a violated **required** field (absent or wrong-shaped) raises
:class:`ArtifactError`, a looser deviation warns and the run continues, and an
unregistered file type is not checked. Distinct from the inline LLM-output schemas,
which constrain a model response rather than a file on disk. → DECISIONS.md §R5.
"""

from __future__ import annotations

import functools
import json
import re
from pathlib import Path
from typing import Any

import jsonschema

from dast_orchestrator.foundation import ui

REPO_ROOT = Path(__file__).resolve().parents[3]
SCHEMAS_DIR = REPO_ROOT / "schemas"

#: Artifact basename (matched as a regex) -> schema file. Ordered; the first match
#: wins. The families cover the suffixed variants (``triage-<suffix>.json``) and
#: the per-kind metrics records (``run-metrics-<kind>.json``). ``triage-prompts``
#: is deliberately excluded from the triage family — it is the dry-run prompt dump,
#: a different shape. A basename that matches nothing here is not validated.
_REGISTRY: "tuple[tuple[re.Pattern[str], str], ...]" = (
    # Metrics FIRST: a metrics file is `<kind>-metrics[-<suffix>].json`, and for
    # kind=triage that is `triage-metrics.json`, which the triage-result pattern
    # below would otherwise claim (reading "metrics" as an out-suffix). Only a
    # name containing `-metrics` matches here, so ordering it first is safe.
    (re.compile(r"^[^.]+-metrics(-[^.]+)?\.json$"), "run-metrics.schema.json"),
    (re.compile(r"^scan-noir-ai-context\.json$"), "noir-ai-context.schema.json"),
    (re.compile(r"^scan-noir-seed-map\.json$"), "noir-seed-map.schema.json"),
    (re.compile(r"^scan-zap-alerts\.json$"), "zap-alerts.schema.json"),
    (re.compile(r"^triage(-(?!prompts)[^.]+)?\.json$"), "triage-result.schema.json"),
    (re.compile(r"^verification(-[^.]+)?\.json$"), "verification-result.schema.json"),
    (re.compile(r"^cve-detection(-[^.]+)?\.json$"), "cve-detection.schema.json"),
    (re.compile(r"^results\.json$"), "harness-results.schema.json"),
)


class ArtifactError(ValueError):
    """A ``data/`` artifact violated a REQUIRED part of its schema on read."""


def schema_file_for(name: str) -> "Path | None":
    """The schema file registered for an artifact basename, or ``None``."""
    for pattern, filename in _REGISTRY:
        if pattern.match(name):
            path = SCHEMAS_DIR / filename
            return path if path.is_file() else None
    return None


@functools.lru_cache(maxsize=None)
def _load_schema(path: Path) -> "dict[str, Any]":
    return json.loads(path.read_text())


def _validator(schema: "dict[str, Any]") -> Any:
    """A draft-appropriate validator for ``schema`` (2020-12 or draft-07)."""
    return jsonschema.validators.validator_for(schema)(schema)


def _is_fatal(error: Any, required: "set[str]") -> bool:
    """A violation is fatal when it is about a REQUIRED field.

    Either a required field is missing (``required`` keyword) or one is present
    with the wrong shape (the error's path starts at a top-level required field).
    Everything else — an optional field's type, an unexpected extra — only warns.
    """
    if error.validator == "required":
        return True
    path = list(error.absolute_path)
    return bool(path) and str(path[0]) in required


def violations(name: str, data: Any) -> "list[str]":
    """Every schema violation for ``data``, as readable ``path: message`` lines.

    Empty when the artifact is valid, or when no schema is registered for ``name``.
    """
    path = schema_file_for(name)
    if path is None:
        return []
    schema = _load_schema(path)
    out = []
    for error in _validator(schema).iter_errors(data):
        where = "/".join(str(p) for p in error.absolute_path) or "<root>"
        out.append(f"{where}: {error.message}")
    return out


def check(name: str, data: Any, source: "str | Path" = "") -> "list[str]":
    """Validate ``data`` (read from an artifact named ``name``) against its schema.

    :raises ArtifactError: if a REQUIRED field is violated (see the module policy).
    :returns: the full list of violations (empty when valid / unregistered); a
        non-fatal set is warned about via :func:`ui.warn` and returned.
    """
    schema_path = schema_file_for(name)
    if schema_path is None:
        return []
    schema = _load_schema(schema_path)
    required = set(schema.get("required", []))
    errors = list(_validator(schema).iter_errors(data))
    if not errors:
        return []

    lines = ["/".join(str(p) for p in e.absolute_path) or "<root>"
             for e in errors]
    detail = "; ".join(
        f"{w}: {e.message}" for w, e in list(zip(lines, errors))[:5]
    ) + (f" … (+{len(errors) - 5} more)" if len(errors) > 5 else "")
    where = f" ({ui.short_path(source)})" if source else ""
    fatal = any(_is_fatal(e, required) for e in errors)

    if fatal:
        raise ArtifactError(
            f"{name}{where} does not match {schema_path.name}: {detail}"
        )
    ui.warn(f"{name}{where} deviates from {schema_path.name} "
            f"(continuing): {detail}")
    return [f"{w}: {e.message}" for w, e in zip(lines, errors)]
