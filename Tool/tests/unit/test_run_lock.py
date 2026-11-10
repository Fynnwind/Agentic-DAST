"""The stage lock: who it refuses, what it reclaims, and when it lets go.

Mechanics only — one module, one directory, no stage started. The wiring (which
stage claims what, and that a refusal reaches the exit code) is
``tests/integration/test_stage_locks.py``.
"""

from __future__ import annotations

import json
import os
import socket
import subprocess

import pytest

from dast_orchestrator.foundation import run_lock


def _dead_pid() -> int:
    """A pid that certainly no longer exists: one we started and waited for."""
    child = subprocess.Popen(["true"])
    child.wait()
    return child.pid


def _write_lock(run_dir, stage, suffix="", **fields):
    path = run_lock.lock_path(run_dir, stage, suffix)
    record = {"stage": stage, "suffix": suffix, "pid": os.getpid(),
              "host": socket.gethostname(), "started": "2026-09-02T18:04:11+00:00",
              "command": "dast verify latest --out-suffix hybrid"}
    record.update(fields)
    path.write_text(json.dumps(record))
    return path


# -- naming ----------------------------------------------------------------


def test_the_suffix_is_part_of_the_name():
    # Two variants of one stage write different artifacts and may run together;
    # that is the whole point of --out-suffix.
    assert run_lock.lock_name("verify", "hybrid") == ".lock-verify-hybrid"
    assert run_lock.lock_name("verify") == ".lock-verify"


# -- refusing --------------------------------------------------------------


def test_a_live_lock_refuses_and_names_the_holder(tmp_path):
    _write_lock(tmp_path, "verify", "hybrid", pid=os.getpid())
    with pytest.raises(run_lock.Busy) as excinfo:
        run_lock.claim(tmp_path, "verify", "hybrid")
    message = str(excinfo.value)
    assert f"pid {os.getpid()}" in message
    assert "--out-suffix hybrid" in message
    assert "dast verify latest --out-suffix hybrid" in message   # the command
    assert "--force" in message                                  # and the way out


def test_a_lock_on_a_different_suffix_does_not_block(tmp_path):
    _write_lock(tmp_path, "verify", "qwen", pid=os.getpid())
    path = run_lock.claim(tmp_path, "verify", "hybrid")
    assert path.name == ".lock-verify-hybrid"
    run_lock.release(path)


def test_a_lock_from_another_host_is_treated_as_live(tmp_path):
    # `os.kill(pid, 0)` answers a question about *this* machine; a pid recorded
    # elsewhere cannot be checked, and "assume free" is the destructive reading.
    _write_lock(tmp_path, "verify", pid=_dead_pid(), host="someone-elses-laptop")
    with pytest.raises(run_lock.Busy, match="someone-elses-laptop"):
        run_lock.claim(tmp_path, "verify")


def test_an_unreadable_lock_is_treated_as_live(tmp_path):
    run_lock.lock_path(tmp_path, "verify").write_text("{ truncated")
    with pytest.raises(run_lock.Busy):
        run_lock.claim(tmp_path, "verify")


# -- reclaiming ------------------------------------------------------------


def test_a_stale_lock_is_reclaimed(tmp_path, capsys):
    stale = _write_lock(tmp_path, "verify", pid=_dead_pid())
    path = run_lock.claim(tmp_path, "verify")
    assert path == stale
    assert json.loads(path.read_text())["pid"] == os.getpid()
    # Reclaiming is not silent: a lock left behind means a previous run died.
    assert "stale" in capsys.readouterr().err


def test_force_takes_over_a_live_lock(tmp_path, capsys):
    _write_lock(tmp_path, "verify", pid=os.getpid(), command="the other one")
    path = run_lock.claim(tmp_path, "verify", force=True)
    assert json.loads(path.read_text())["command"] != "the other one"
    assert "--force" in capsys.readouterr().err


# -- letting go ------------------------------------------------------------


def test_claim_records_who_holds_it(tmp_path):
    path = run_lock.claim(tmp_path, "triage")
    record = json.loads(path.read_text())
    assert record["pid"] == os.getpid()
    assert record["host"] == socket.gethostname()
    assert record["stage"] == "triage" and record["started"]
    run_lock.release(path)
    assert not path.exists()


def test_release_leaves_another_process_lock_alone(tmp_path):
    # Someone reclaimed this lock while we were still running: deleting it now
    # would hand a third process a directory two are already writing to.
    path = _write_lock(tmp_path, "verify", pid=os.getpid() + 1)
    run_lock.release(path)
    assert path.exists()


def test_held_releases_on_the_way_out(tmp_path):
    with pytest.raises(ValueError):
        with run_lock.held(tmp_path, "report") as path:
            assert path.exists()
            raise ValueError("boom")
    assert not path.exists()


def test_the_run_directory_is_created_if_it_is_not_there_yet(tmp_path):
    # `scan` claims the moment it mints its run id, before the directory the run
    # is about to write into exists.
    run_dir = tmp_path / "20260902T120000Z-gitea-a3f19c"
    path = run_lock.claim(run_dir, "scan")
    assert path.exists()
    run_lock.release(path)


# -- the guard around a stage's main ---------------------------------------


def test_guarded_releases_whatever_the_call_claimed(tmp_path):
    @run_lock.guarded
    def main() -> int:
        run_lock.claim(tmp_path, "verify", "hybrid")
        return 0

    assert main() == 0
    assert not run_lock.lock_path(tmp_path, "verify", "hybrid").exists()
    # …and the run is repeatable, which is what the harness does all night.
    assert main() == 0


def test_guarded_releases_on_an_early_return_and_on_an_exception(tmp_path):
    @run_lock.guarded
    def main(explode: bool) -> int:
        run_lock.claim(tmp_path, "verify")
        if explode:
            raise RuntimeError("stage failed")
        return 1

    assert main(False) == 1
    assert not run_lock.lock_path(tmp_path, "verify").exists()
    with pytest.raises(RuntimeError):
        main(True)
    assert not run_lock.lock_path(tmp_path, "verify").exists()


def test_guarded_turns_a_refusal_into_an_exit_code(tmp_path, capsys):
    _write_lock(tmp_path, "verify", pid=os.getpid())

    @run_lock.guarded
    def main() -> int:
        run_lock.claim(tmp_path, "verify")
        raise AssertionError("unreachable: the claim refuses")

    assert main() == run_lock.BUSY_EXIT
    assert "ERROR: verify is already running" in capsys.readouterr().err


def test_one_stage_does_not_release_another_stages_lock(tmp_path):
    # `dast triage verify latest` runs both mains in one process.
    @run_lock.guarded
    def inner() -> int:
        run_lock.claim(tmp_path, "verify")
        return 0

    @run_lock.guarded
    def outer() -> int:
        run_lock.claim(tmp_path, "triage")
        assert inner() == 0
        assert not run_lock.lock_path(tmp_path, "verify").exists()
        assert run_lock.lock_path(tmp_path, "triage").exists()
        return 0

    assert outer() == 0
    assert not run_lock.lock_path(tmp_path, "triage").exists()
