"""A run's self-description: ``manifest.json`` lists the artifacts present in a run
directory, each with the schema that governs it and its ``schema_version``.

Regenerated (a full scan of the directory, so it never drifts from disk) whenever a
stage records metrics. It lets a reader — the report, the analyzer, a person — learn
what a run contains by reading ONE file, instead of probing well-known names.
→ docs/DATA.md.
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from dast_orchestrator.foundation import run_paths, schema

MANIFEST = run_paths.MANIFEST

#: `schema_version` is a small top-level int; read it from the file's head rather
#: than parsing artifacts that can be megabytes (scan-zap-messages).
_VERSION_RE = re.compile(rb'"schema_version"\s*:\s*(\d+)')
_HEAD_BYTES = 4096


def _schema_version(path: Path) -> "int | None":
    try:
        with path.open("rb") as fh:
            head = fh.read(_HEAD_BYTES)
    except OSError:
        return None
    m = _VERSION_RE.search(head)
    return int(m.group(1)) if m else None


def build_manifest(layout: run_paths.RunLayout) -> dict[str, Any]:
    """Describe every artifact in ``layout.dir`` — name, size, schema, version."""
    artifacts: list[dict[str, Any]] = []
    if layout.dir.is_dir():
        for p in sorted(layout.dir.iterdir()):
            if not p.is_file() or p.name == MANIFEST or p.name.startswith("."):
                continue
            entry: dict[str, Any] = {"file": p.name, "bytes": p.stat().st_size}
            sf = schema.schema_file_for(p.name)
            entry["schema"] = sf.name if sf else None
            version = _schema_version(p) if p.suffix == ".json" else None
            if version is not None:
                entry["schema_version"] = version
            artifacts.append(entry)
    return {
        "run": layout.run_id,
        "generated_at": datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ"),
        "artifacts": artifacts,
    }


def write_manifest(layout: run_paths.RunLayout) -> Path:
    """(Re)write ``manifest.json`` for a run. Best-effort: a manifest is a
    convenience, so a failure here never fails the stage that triggered it."""
    path = layout.path(MANIFEST)
    path.write_text(json.dumps(build_manifest(layout), indent=2))
    return path
