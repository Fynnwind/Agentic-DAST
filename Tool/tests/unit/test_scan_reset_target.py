"""The --reset-target reset step (`pipeline.reset_target_to_clean_state`).

Runs the target's own env/reset.sh. Hermetic: the stub scripts are plain bash,
no Docker — the live reset is the script's job, exercised in the e2e tier.
"""

from __future__ import annotations

import os
import subprocess

import pytest

from dast_orchestrator.adapters import targets
from dast_orchestrator.stages.scan import pipeline


def _all_target_dirs():
    """Every real target directory (one per ``target.yml``)."""
    return sorted(p.parent for p in targets.TARGETS_DIR.glob(f"*/{targets.DEFINITION_NAME}"))


def _reset_script(target_dir, body):
    env = target_dir / "env"
    env.mkdir(parents=True, exist_ok=True)
    script = env / "reset.sh"
    script.write_text("#!/usr/bin/env bash\n" + body + "\n")
    return script


def test_reset_runs_the_targets_reset_script(tmp_path):
    _reset_script(tmp_path, "exit 0")
    assert pipeline.reset_target_to_clean_state("x", tmp_path).name == "reset.sh"


def test_reset_errors_when_the_target_has_no_script(tmp_path):
    with pytest.raises(RuntimeError, match="reinitialise"):
        pipeline.reset_target_to_clean_state("x", tmp_path)


def test_reset_errors_and_surfaces_stderr_on_failure(tmp_path):
    _reset_script(tmp_path, "echo 'stack not up' >&2\nexit 3")
    with pytest.raises(RuntimeError, match=r"failed \(exit 3\).*stack not up"):
        pipeline.reset_target_to_clean_state("x", tmp_path)


# -- --reset-target is a GENERAL flag: every target must ship a reset.sh --------


@pytest.mark.parametrize("target_dir", _all_target_dirs(), ids=lambda d: d.name)
def test_every_target_ships_an_executable_reset_script(target_dir):
    """``--reset-target`` is target-agnostic (``reset_target_to_clean_state``
    runs ``<target>/env/reset.sh`` for whichever target is scanned), so a target
    without one makes the flag fail fast against it. Every target directory must
    therefore carry an executable ``env/reset.sh`` — a new target that forgets
    one fails here, the same way a marker with no rescan-table row fails the
    ground-truth glob test. The script's live effect (Docker snapshot/restore)
    is the e2e tier's job; here we assert the file, its bit, the snapshot/restore
    contract and that it is valid bash.
    """
    script = target_dir / "env" / "reset.sh"
    assert script.is_file(), f"{target_dir.name} has no env/reset.sh"
    assert os.access(script, os.X_OK), f"{target_dir.name}/env/reset.sh is not executable"
    body = script.read_text()
    assert "--snapshot" in body, f"{target_dir.name}/env/reset.sh has no --snapshot capture path"
    assert "data-snapshot.tar" in body, f"{target_dir.name}/env/reset.sh names no snapshot artifact"
    assert subprocess.run(["bash", "-n", str(script)]).returncode == 0, (
        f"{target_dir.name}/env/reset.sh is not valid bash"
    )
