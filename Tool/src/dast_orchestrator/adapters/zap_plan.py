"""The Automation Framework mode (``SCAN_ZAP_MODE=af``): run a ZAP AF plan (one YAML file)
instead of the default explicit REST sequence.

The REST path stays the default; AF is opt-in because it is how ZAP is normally driven in
CI, which matters for a thesis about DAST in CI/CD. The plan is ``docker cp``'d in and run
from ``/tmp`` (the daemon has no bind mount); it is not versioned like prompts but its
SHA-256 is recorded, and since ZAP silently runs an unrecognised job type, the job list ZAP
echoes back is recorded as the only evidence of what ran. → DECISIONS.md.
"""

from __future__ import annotations

import hashlib
import subprocess
import time
from pathlib import Path
from typing import Any

from dast_orchestrator.foundation import ui
from dast_orchestrator.adapters.zap_client import ZapClient

#: Where a target's own plan lives, if it has one. A file here is used
#: automatically in ``SCAN_ZAP_MODE=af`` — the target knows best how it wants to be
#: scanned, and putting the plan beside the rest of the target's data keeps it
#: with the thing it describes.
PLAN_BASENAME = "zap.yml"

#: Where the plan is copied to inside the daemon container.
CONTAINER_PLAN_PATH = "/tmp/dast-zap-plan.yml"

#: How often the plan's progress is polled, in seconds. A plan runs whole jobs
#: between updates, so polling faster only adds log noise.
POLL_SECONDS = 5.0


class PlanError(RuntimeError):
    """The plan could not be found, delivered, or run."""


def plan_for_target(target_name: str, targets_dir: Path) -> "Path | None":
    """The plan shipped with a target, or ``None``."""
    candidate = Path(targets_dir) / target_name / PLAN_BASENAME
    return candidate if candidate.is_file() else None


def resolve_plan(explicit: "str | Path | None", target_name: str,
                 targets_dir: Path) -> "Path | None":
    """Which plan a run should use: the named one, else the target's own.

    An explicitly named file that does not exist is an error rather than a
    silent fall-through to the target's: naming a plan is a statement about how
    this run should be driven, and quietly running a different one would be the
    worst possible answer.
    """
    if explicit:
        path = Path(explicit)
        if not path.is_file():
            raise PlanError(f"no automation plan at {path}")
        return path
    return plan_for_target(target_name, targets_dir)


def plan_digest(path: Path) -> str:
    """SHA-256 of the plan's bytes, so a result can be tied to the file.

    Bytes, not parsed YAML: the question this answers is "is this the same file
    that produced that run", and a reformat that changes nothing semantically
    still changes the file a reader is holding.
    """
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def deliver(path: Path, container: str) -> str:
    """Copy the plan into the daemon container; return the path inside it."""
    try:
        result = subprocess.run(
            ["docker", "cp", str(path), f"{container}:{CONTAINER_PLAN_PATH}"],
            capture_output=True, text=True, timeout=30,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise PlanError(f"could not copy the plan into {container}: {exc}") from exc
    if result.returncode != 0:
        raise PlanError(
            f"could not copy the plan into {container}: "
            f"{result.stderr.strip() or result.stdout.strip()}"
        )
    return CONTAINER_PLAN_PATH


def run_plan(zap: ZapClient, container_path: str,
             poll_seconds: float = POLL_SECONDS) -> dict[str, Any]:
    """Run a delivered plan to completion and return what ZAP reported.

    The returned ``info`` list is the only record of which jobs actually ran, so
    it is kept whole rather than summarised — see the module docstring on
    unrecognised job types passing silently.
    """
    plan_id = zap.run_plan(container_path)
    ui.step(f"[af] plan {plan_id} started")
    seen = 0
    while True:
        progress = zap.plan_progress(plan_id)
        info = progress.get("info") or []
        for line in info[seen:]:
            ui.step(f"[af] {line}")
        seen = len(info)
        if progress.get("finished"):
            break
        time.sleep(poll_seconds)

    for warning in progress.get("warn") or []:
        ui.warn(f"plan: {warning}")
    for error in progress.get("error") or []:
        ui.warn(f"plan ERROR: {error}")
    return progress
