"""Discover and load the per-stage metric records that are the analyzer's spine.

One file = one stage execution. The index is built from these records and never
from a harness ``results.json`` summary (RUN-PLAN §8). Record files are named
``<stage>-metrics.json`` (minting / base rows) or ``<stage>-metrics-<label>.json``
(the suffixed G5-G8 re-runs written back into the reference scan dir); both are
real executions, so both are loaded. A record carries its own provenance
(``run``, ``harness_id``, ``harness_row``, ``label``, ``config``), which is why a
suffixed file physically sitting in a campaign-1 scan dir still reports the
campaign-4/5 launch that produced it.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterator

# Stage records only — not cve-detection.json, not the artifacts themselves.
_RECORD_RE = re.compile(r"^(scan|triage|verify|report|analysis)-metrics(-.+)?\.json$")

# The one pilot sheet (RUN-PLAN §1): built the analyzer, never reported.
PILOT_HARNESS_MARKER = "canonical-baseline"


@dataclass
class StageRecord:
    """A loaded stage-metrics record plus where it was read from."""

    data: dict[str, Any]
    path: Path
    run_dir: Path
    data_root: Path

    @property
    def kind(self) -> str:
        return self.data.get("kind", "")

    @property
    def run(self) -> str:
        return self.data.get("run", self.run_dir.name)

    @property
    def harness_id(self) -> str:
        return self.data.get("harness_id", "")

    @property
    def harness_row(self) -> str:
        return self.data.get("harness_row", "")

    @property
    def label(self) -> str:
        return self.data.get("label", "")

    @property
    def is_pilot(self) -> bool:
        return PILOT_HARNESS_MARKER in self.harness_id or PILOT_HARNESS_MARKER in str(
            self.run_dir
        )

    @property
    def aborted(self) -> bool:
        return bool(self.data.get("abort"))

    @property
    def config_digest(self) -> str:
        """The trailing hash of the run id (``…-gitea-2865f0`` -> ``2865f0``)."""
        return self.run.rsplit("-", 1)[-1] if "-" in self.run else ""


def iter_record_files(root: Path) -> Iterator[Path]:
    """Yield every stage-record file under ``root`` (a data tree or a run dir)."""
    root = Path(root)
    if root.is_file():
        if _RECORD_RE.match(root.name):
            yield root
        return
    for path in sorted(root.rglob("*-metrics*.json")):
        if _RECORD_RE.match(path.name):
            yield path


def load_records(roots: list[Path] | Path) -> list[StageRecord]:
    """Load all stage records under one or more roots, de-duplicated by file path."""
    if isinstance(roots, (str, Path)):
        roots = [Path(roots)]
    seen: set[Path] = set()
    out: list[StageRecord] = []
    for root in roots:
        root = Path(root)
        for path in iter_record_files(root):
            rp = path.resolve()
            if rp in seen:
                continue
            seen.add(rp)
            try:
                data = json.loads(path.read_text())
            except (json.JSONDecodeError, OSError) as exc:  # pragma: no cover - corpus is clean
                raise ValueError(f"unreadable record {path}: {exc}") from exc
            out.append(
                StageRecord(
                    data=data,
                    path=path,
                    run_dir=path.parent,
                    data_root=root,
                )
            )
    return out
